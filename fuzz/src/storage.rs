//! Harness-only publication outcomes; no production fault controls.

use p256::elliptic_curve::zeroize::Zeroizing;
use pqkey_ctap::store::{
    AttestationRecord, CommitDurability, CredentialCommit, CredentialRecord, CredentialStore,
    MemoryStore, PinStateRecord, StoreError,
};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(crate) struct Write {
    pub state: PinStateRecord,
    pub outcome: Option<CommitDurability>,
}

struct State {
    store: MemoryStore,
    fault: Option<(u8, usize)>,
    writes: Vec<Write>,
}

#[derive(Clone)]
pub(crate) struct HarnessStore(Arc<Mutex<State>>);

impl HarnessStore {
    pub fn new(store: MemoryStore) -> Self {
        Self(Arc::new(Mutex::new(State {
            store,
            fault: None,
            writes: Vec::new(),
        })))
    }

    pub fn schedule(&self, mode: u8, after: u8) {
        self.0.lock().unwrap().fault = Some((mode % 4, usize::from(after % 4)));
    }

    pub fn take_writes(&self) -> Vec<Write> {
        std::mem::take(&mut self.0.lock().unwrap().writes)
    }
}

impl State {
    fn publication(&mut self, record: &PinStateRecord) -> Result<CommitDurability, StoreError> {
        let mode = match self.fault.as_mut() {
            Some((mode, 0)) => {
                let mode = *mode;
                self.fault = None;
                mode
            }
            Some((_, remaining)) => {
                *remaining -= 1;
                0
            }
            None => 0,
        };
        let outcome = match mode {
            0 => Some(CommitDurability::Volatile),
            1 => Some(CommitDurability::Flushed),
            2 => None,
            _ => Some(CommitDurability::Unconfirmed),
        };
        self.writes.push(Write {
            state: record.clone(),
            outcome,
        });
        outcome.ok_or(StoreError::Io {
            path: "fuzz-pin-state".into(),
            source: std::io::Error::other("injected pre-publication failure"),
        })
    }
}

impl CredentialStore for HarnessStore {
    fn get(&self, id: &[u8]) -> Result<Option<CredentialRecord>, StoreError> {
        self.0.lock().unwrap().store.get(id)
    }
    fn put(&mut self, record: &CredentialRecord) -> Result<(), StoreError> {
        self.0.lock().unwrap().store.put(record)
    }
    fn insert_or_replace_discoverable(
        &mut self,
        record: &CredentialRecord,
    ) -> Result<CredentialCommit, StoreError> {
        self.0
            .lock()
            .unwrap()
            .store
            .insert_or_replace_discoverable(record)
    }
    fn delete(&mut self, id: &[u8]) -> Result<bool, StoreError> {
        self.0.lock().unwrap().store.delete(id)
    }
    fn list(&self) -> Result<Vec<CredentialRecord>, StoreError> {
        self.0.lock().unwrap().store.list()
    }
    fn count(&self) -> Result<usize, StoreError> {
        self.0.lock().unwrap().store.count()
    }
    fn max_credentials(&self) -> usize {
        self.0.lock().unwrap().store.max_credentials()
    }
    fn clear(&mut self) -> Result<CommitDurability, StoreError> {
        let mut state = self.0.lock().unwrap();
        let outcome = state.publication(&PinStateRecord::default())?;
        state.store.clear()?;
        Ok(outcome)
    }
    fn pin_state(&self) -> Result<Option<PinStateRecord>, StoreError> {
        self.0.lock().unwrap().store.pin_state()
    }
    fn set_pin_state(&mut self, record: &PinStateRecord) -> Result<CommitDurability, StoreError> {
        let mut state = self.0.lock().unwrap();
        let outcome = state.publication(record)?;
        state.store.set_pin_state(record)?;
        Ok(outcome)
    }
    fn signature_counter(&self) -> Result<u32, StoreError> {
        self.0.lock().unwrap().store.signature_counter()
    }
    fn set_signature_counter(&mut self, value: u32) -> Result<(), StoreError> {
        self.0.lock().unwrap().store.set_signature_counter(value)
    }
    fn large_blob_array(&self) -> Result<Vec<u8>, StoreError> {
        self.0.lock().unwrap().store.large_blob_array()
    }
    fn set_large_blob_array(&mut self, array: &[u8]) -> Result<(), StoreError> {
        self.0.lock().unwrap().store.set_large_blob_array(array)
    }
    fn attestation(&self) -> Result<Option<AttestationRecord>, StoreError> {
        self.0.lock().unwrap().store.attestation()
    }
    fn set_attestation(&mut self, record: &AttestationRecord) -> Result<(), StoreError> {
        self.0.lock().unwrap().store.set_attestation(record)
    }
    fn seal_credential_id(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.0
            .lock()
            .unwrap()
            .store
            .seal_credential_id(plaintext, ad)
    }
    fn open_credential_id(
        &self,
        sealed: &[u8],
        ad: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        self.0.lock().unwrap().store.open_credential_id(sealed, ad)
    }
}
