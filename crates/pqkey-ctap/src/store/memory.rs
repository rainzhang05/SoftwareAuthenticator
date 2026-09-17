//! An in-memory [`CredentialStore`] for tests of the CTAP engine.

use std::collections::BTreeMap;

use super::{
    next_created_at, sort_newest_first, validate_attestation, validate_credential,
    AttestationRecord, CredentialRecord, CredentialStore, PinStateRecord, StoreError,
    DEFAULT_MAX_CREDENTIALS,
};

/// A [`CredentialStore`] that keeps everything in memory.
///
/// It follows the same rules as the file-backed store: newest-first
/// ordering with store-assigned creation order, the credential limit applies to
/// inserts but not to replacements, records are validated before they are
/// accepted, and [`clear`](CredentialStore::clear) keeps the attestation record
/// and leaves a default PIN state behind.  Nothing is ever corrupt, and there
/// is no size limit on individual records.
#[derive(Debug)]
pub struct MemoryStore {
    credentials: BTreeMap<Vec<u8>, CredentialRecord>,
    pin_state: Option<PinStateRecord>,
    attestation: Option<AttestationRecord>,
    max_credentials: usize,
}

impl MemoryStore {
    /// An empty store with [`DEFAULT_MAX_CREDENTIALS`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            credentials: BTreeMap::new(),
            pin_state: None,
            attestation: None,
            max_credentials: DEFAULT_MAX_CREDENTIALS,
        }
    }

    /// Set the credential limit.
    #[must_use]
    pub fn with_max_credentials(mut self, max_credentials: usize) -> Self {
        self.max_credentials = max_credentials;
        self
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore for MemoryStore {
    fn get(&self, credential_id: &[u8]) -> Result<Option<CredentialRecord>, StoreError> {
        Ok(self.credentials.get(credential_id).cloned())
    }

    fn put(&mut self, record: &CredentialRecord) -> Result<(), StoreError> {
        validate_credential(record)?;
        let created_at = match self.credentials.get(&record.credential_id) {
            Some(existing) => existing.created_at,
            None => {
                if self.credentials.len() >= self.max_credentials {
                    return Err(StoreError::Full {
                        max: self.max_credentials,
                    });
                }
                next_created_at(self.credentials.values())
            }
        };
        let mut stored = record.clone();
        stored.created_at = created_at;
        self.credentials
            .insert(stored.credential_id.clone(), stored);
        Ok(())
    }

    fn delete(&mut self, credential_id: &[u8]) -> Result<bool, StoreError> {
        Ok(self.credentials.remove(credential_id).is_some())
    }

    fn list(&self) -> Result<Vec<CredentialRecord>, StoreError> {
        let mut records: Vec<_> = self.credentials.values().cloned().collect();
        sort_newest_first(&mut records);
        Ok(records)
    }

    fn count(&self) -> Result<usize, StoreError> {
        Ok(self.credentials.len())
    }

    fn max_credentials(&self) -> usize {
        self.max_credentials
    }

    fn clear(&mut self) -> Result<(), StoreError> {
        self.credentials.clear();
        self.pin_state = Some(PinStateRecord::default());
        Ok(())
    }

    fn pin_state(&self) -> Result<Option<PinStateRecord>, StoreError> {
        Ok(self.pin_state.clone())
    }

    fn set_pin_state(&mut self, state: &PinStateRecord) -> Result<(), StoreError> {
        self.pin_state = Some(state.clone());
        Ok(())
    }

    fn attestation(&self) -> Result<Option<AttestationRecord>, StoreError> {
        Ok(self.attestation.clone())
    }

    fn set_attestation(&mut self, record: &AttestationRecord) -> Result<(), StoreError> {
        validate_attestation(record)?;
        self.attestation = Some(record.clone());
        Ok(())
    }
}
