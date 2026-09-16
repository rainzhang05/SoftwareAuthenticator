//! Persistent storage for credentials, PIN state, and attestation material.
//!
//! [`CredentialStore`] is the interface the CTAP engine talks to.  It has two
//! implementations with the same observable behaviour:
//!
//! * [`MemoryStore`] keeps everything in memory, for tests of the CTAP engine.
//! * [`FileStore`] is the production backend: one authenticated, encrypted
//!   file per record in a private state directory.  Its on-disk format is
//!   specified in the [`FileStore`] documentation.
//!
//! There is no practical limit on record size (the file store accepts up to
//! 1 MiB per record, and a post-quantum credential takes a few hundred bytes
//! because ML-DSA keys are stored as their 32-byte seed), and no limit on the
//! number of credentials other than the configurable
//! [`CredentialStore::max_credentials`].
//!
//! # Threat model
//!
//! [`FileStore`] encrypts and authenticates every record with
//! XChaCha20-Poly1305.  With the default [`FileKeySource`] the root keys are
//! files in the same state directory as the data, so be precise about what
//! that buys.
//!
//! **Encryption at rest does not protect against anyone who can read the whole
//! state directory as the same user, or as root.**  Such an attacker reads the
//! key files and decrypts everything, private keys included.  The `0700`
//! directory and `0600` file permissions are the access control, and they only
//! keep out other unprivileged local users.  Likewise, the stored PIN hash is
//! `LEFT(SHA-256(PIN), 16)`, which such an attacker can brute-force offline;
//! the PIN retry counter only limits guessing through CTAP.
//!
//! What the encryption does provide:
//!
//! * **Integrity of each file.**  The authentication tag covers the record
//!   type and the file's name, so a modified, truncated, or swapped file is
//!   reported as [`StoreError::Corrupt`] and never used.  It is per-file
//!   integrity, not integrity of the store as a whole: deleting a file is not
//!   detected, and neither is replacing a file with an older copy of itself
//!   made since the last reset, which rolls back a signature counter or the PIN
//!   retry counter.  Anyone holding the keys can of course forge records.
//! * **Crypto-shredding on reset.**  [`CredentialStore::clear`] replaces the key
//!   that protects credentials and PIN state.  Overwriting files does not
//!   reliably destroy data on SSDs or copy-on-write filesystems, but old
//!   ciphertext left in free blocks, snapshots, or backups is useless once its
//!   key is gone.  The old key file is overwritten before it is released, as a
//!   best effort; on the same kinds of media that 32-byte file can survive too,
//!   which is the gap an OS-backed key source closes.
//! * **No plaintext secrets in copies that leave out the key files**, such as
//!   a backup or disk image that excludes `keys/`.  Most backup tools copy
//!   whole directories, so this only helps if the exclusion is deliberate.
//! * **A seam for OS-backed key storage.**  Root keys come from a
//!   [`KeySource`].  Keeping them in systemd-creds, a TPM, or the Secret
//!   Service changes the answer to the first point without changing
//!   [`FileStore`].
//!
//! # Corruption
//!
//! A record that fails authentication or decoding never crashes the
//! authenticator and is never deleted automatically.  [`CredentialStore::get`],
//! [`CredentialStore::pin_state`], and [`CredentialStore::attestation`] report
//! it as [`StoreError::Corrupt`]; [`CredentialStore::list`] and
//! [`CredentialStore::count`] skip it with a logged warning, so one bad file
//! cannot hide the others.  It stays on disk until it is overwritten, deleted
//! with [`CredentialStore::delete`], or removed by [`CredentialStore::clear`].
//!
//! # Concurrency
//!
//! A store assumes one writer at a time.  Several processes may open the same
//! state directory: every operation re-reads the root keys, so a reset
//! performed by one process takes effect in the others, and first-time key
//! creation is race-free.  Mutations are not otherwise coordinated between
//! processes, so two concurrent writers can exceed the credential limit or
//! assign two credentials the same creation order.

use core::fmt;
use std::io;
use std::path::PathBuf;

mod codec;
mod envelope;
mod file;
mod fsio;
mod keys;
mod memory;
mod record;
#[cfg(test)]
mod test_support;

pub use file::FileStore;
pub use keys::{FileKeySource, KeyDomain, KeySource, RootKey};
pub use memory::MemoryStore;
pub use record::{AttestationRecord, CredentialRecord, PinStateRecord, PrivateKeyMaterial};

/// The credential limit a store uses unless configured otherwise.
pub const DEFAULT_MAX_CREDENTIALS: usize = 1000;

/// Storage for discoverable credentials, the persistent PIN state, and the
/// attestation key.
///
/// Every implementation must behave identically; the conformance tests in
/// `authenticator/tests/store` run the same cases against each of them.
pub trait CredentialStore {
    /// Load the credential with this ID.
    ///
    /// Returns `Ok(None)` if no such credential is stored, and
    /// [`StoreError::Corrupt`] if one is stored but cannot be authenticated or
    /// decoded.
    fn get(&self, credential_id: &[u8]) -> Result<Option<CredentialRecord>, StoreError>;

    /// Insert `record`, or replace the stored credential with the same ID.
    ///
    /// The write is atomic: afterwards the store holds either the previous
    /// state or the new record, never a mixture.  An insert is assigned a
    /// fresh creation order and a replacement keeps the stored one; the
    /// `created_at` in `record` is ignored (see [`CredentialRecord`]).
    ///
    /// Returns [`StoreError::Full`] when inserting would exceed
    /// [`Self::max_credentials`]; replacing an existing credential always
    /// succeeds.  Returns [`StoreError::InvalidRecord`], and stores nothing,
    /// if `record` is inconsistent: an empty credential ID, an `alg` that does
    /// not match the key material, an invalid P-256 scalar, or a `cred_protect`
    /// outside 1–3.
    fn put(&mut self, record: &CredentialRecord) -> Result<(), StoreError>;

    /// Delete the credential with this ID, returning whether one was stored.
    ///
    /// A credential that is stored but corrupt is deleted too.
    fn delete(&mut self, credential_id: &[u8]) -> Result<bool, StoreError>;

    /// Every readable credential, most recently created first.
    ///
    /// Corrupt credentials are skipped and logged rather than failing the
    /// whole listing.
    fn list(&self) -> Result<Vec<CredentialRecord>, StoreError>;

    /// The number of readable credentials, which is always `list()?.len()`.
    fn count(&self) -> Result<usize, StoreError>;

    /// The most credentials this store will hold.
    fn max_credentials(&self) -> usize;

    /// Factory reset: delete every credential and reset the PIN state to
    /// [`PinStateRecord::default`].  The attestation record is kept.
    ///
    /// Afterwards [`Self::pin_state`] returns the default state, not `None`.
    /// [`FileStore`] also replaces the key protecting credentials and PIN
    /// state, so any copy of the old files becomes undecryptable.  This is
    /// destructive by design; call it only on an explicit reset request.
    fn clear(&mut self) -> Result<(), StoreError>;

    /// The persistent PIN state, or `None` if it has never been written.
    fn pin_state(&self) -> Result<Option<PinStateRecord>, StoreError>;

    /// Atomically replace the persistent PIN state.
    fn set_pin_state(&mut self, state: &PinStateRecord) -> Result<(), StoreError>;

    /// The attestation record, or `None` if none has been provisioned.
    fn attestation(&self) -> Result<Option<AttestationRecord>, StoreError>;

    /// Atomically replace the attestation record.
    ///
    /// Returns [`StoreError::InvalidRecord`] for an invalid P-256 scalar, an
    /// empty certificate chain, or an empty certificate.
    fn set_attestation(&mut self, record: &AttestationRecord) -> Result<(), StoreError>;
}

/// Why a stored object was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Corruption {
    /// The object is too short to hold an envelope, or larger than any valid
    /// record.
    Length,
    /// The magic bytes, format version, or record type are wrong.
    Header,
    /// The authentication tag does not verify: the object was modified,
    /// truncated, moved to another name, or encrypted under a different key.
    Authentication,
    /// The authenticated plaintext is not a well-formed record.
    Encoding,
    /// The record is well formed but violates an invariant, for example its
    /// `alg` disagrees with its key material or its credential ID does not
    /// belong to the file it was read from.
    Inconsistent,
}

impl fmt::Display for Corruption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Corruption::Length => "invalid length",
            Corruption::Header => "unrecognised header",
            Corruption::Authentication => "authentication failed",
            Corruption::Encoding => "malformed record encoding",
            Corruption::Inconsistent => "inconsistent record contents",
        })
    }
}

/// Errors reported by a [`CredentialStore`] or a [`KeySource`].
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// Reading or writing the backing storage failed.
    Io {
        /// The file or directory being accessed.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// A stored object exists but failed authentication or decoding.  It is
    /// left in place.
    Corrupt {
        /// The object's logical name, for example `pin-state` or
        /// `credentials/<64 hex digits>`.
        object: String,
        /// What was wrong with it.
        reason: Corruption,
    },
    /// A root key exists but cannot be used, or is missing although data
    /// encrypted under it exists.  Keys are never regenerated implicitly,
    /// because that would orphan every record they protect; restore the key or
    /// reset the store.
    KeyUnavailable {
        /// The key domain concerned.
        domain: KeyDomain,
        /// A human-readable explanation.
        detail: String,
    },
    /// Inserting a new credential would exceed the credential limit.
    Full {
        /// The configured limit.
        max: usize,
    },
    /// The record passed to a write violates an invariant; nothing was
    /// written.
    InvalidRecord(&'static str),
    /// The operating system's random number generator failed.
    Random,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            StoreError::Corrupt { object, reason } => write!(f, "{object} is corrupt: {reason}"),
            StoreError::KeyUnavailable { domain, detail } => {
                write!(f, "{domain} root key unavailable: {detail}")
            }
            StoreError::Full { max } => write!(f, "credential store is full ({max} credentials)"),
            StoreError::InvalidRecord(reason) => write!(f, "invalid record: {reason}"),
            StoreError::Random => {
                f.write_str("the operating system random number generator failed")
            }
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Check the invariants every stored credential satisfies.
pub(crate) fn validate_credential(record: &CredentialRecord) -> Result<(), StoreError> {
    if record.credential_id.is_empty() {
        return Err(StoreError::InvalidRecord("credential ID is empty"));
    }
    if !record.private_key.matches(record.alg) {
        return Err(StoreError::InvalidRecord(
            "alg does not match the private key material",
        ));
    }
    if let PrivateKeyMaterial::Es256 { scalar } = &record.private_key {
        if p256::SecretKey::from_slice(scalar).is_err() {
            return Err(StoreError::InvalidRecord(
                "ES256 private key is not a valid P-256 scalar",
            ));
        }
    }
    if !(1..=3).contains(&record.cred_protect) {
        return Err(StoreError::InvalidRecord(
            "credProtect level must be 1, 2 or 3",
        ));
    }
    Ok(())
}

/// Check the invariants every stored attestation record satisfies.
pub(crate) fn validate_attestation(record: &AttestationRecord) -> Result<(), StoreError> {
    if p256::SecretKey::from_slice(&record.private_key).is_err() {
        return Err(StoreError::InvalidRecord(
            "attestation private key is not a valid P-256 scalar",
        ));
    }
    if record.certificate_chain.is_empty() {
        return Err(StoreError::InvalidRecord(
            "attestation certificate chain is empty",
        ));
    }
    if record.certificate_chain.iter().any(Vec::is_empty) {
        return Err(StoreError::InvalidRecord(
            "attestation certificate is empty",
        ));
    }
    Ok(())
}

/// Sort most recently created first.  Creation orders are unique within a
/// store; the credential ID only makes the order total should a concurrent
/// writer have produced a tie.
///
/// The sort is in place: a stable sort would copy records, secrets included,
/// into a scratch buffer that is freed without being wiped.  The key is unique
/// per record, so stability would not change the result anyway.
pub(crate) fn sort_newest_first(records: &mut [CredentialRecord]) {
    records.sort_unstable_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.credential_id.cmp(&b.credential_id))
    });
}

/// The creation order for a credential inserted next to `existing`: one more
/// than the newest, starting at 1.
///
/// Stores only ever assign values this way, so reaching `u64::MAX` takes a
/// forged record.  Saturating then produces a tie, which [`sort_newest_first`]
/// still orders deterministically, rather than refusing every future insert.
pub(crate) fn next_created_at<'a>(existing: impl IntoIterator<Item = &'a CredentialRecord>) -> u64 {
    existing
        .into_iter()
        .map(|record| record.created_at)
        .max()
        .map_or(1, |newest| newest.saturating_add(1))
}
