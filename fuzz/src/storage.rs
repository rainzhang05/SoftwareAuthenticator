//! Harness-only publication outcomes and store faults; no production fault
//! controls.
//!
//! The store records every call the engine makes, in order, with the fault
//! it met, so the sequence model can tell what the engine read and wrote.
//! Faults fail a call before it changes anything, as the file store's do:
//! its writes either publish or leave the preceding state, and a read error
//! leaves the stored record as it was.

use p256::elliptic_curve::zeroize::Zeroizing;
use pqkey_ctap::store::{
    AttestationRecord, CommitDurability, Corruption, CredentialCommit, CredentialRecord,
    CredentialStore, MemoryStore, PinStateRecord, StoreError,
};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone)]
pub(crate) struct Write {
    pub state: PinStateRecord,
    pub outcome: Option<CommitDurability>,
}

/// A store call the engine made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Call {
    PinRead,
    /// A PIN-state publication: `set_pin_state`, or the default state
    /// `clear` publishes.
    PinWrite,
    Get,
    List,
    Count,
    Put,
    Insert,
    Delete,
    CounterRead,
    CounterWrite,
    BlobRead,
    BlobWrite,
}

impl Call {
    /// The fault slot of the call (see [`HarnessStore::schedule_fault`]).
    fn slot(self) -> usize {
        match self {
            Call::PinRead => 0,
            Call::Get => 1,
            Call::List | Call::Count => 2,
            Call::Put | Call::Insert | Call::Delete => 3,
            Call::CounterRead => 4,
            Call::CounterWrite => 5,
            Call::BlobRead => 6,
            Call::BlobWrite => 7,
            Call::PinWrite => unreachable!("PIN-state publication has its own schedule"),
        }
    }

    fn object(self) -> &'static str {
        match self {
            Call::PinRead | Call::PinWrite => "pin-state",
            Call::Get | Call::Put | Call::Insert | Call::Delete => "credentials/fuzz",
            Call::List | Call::Count => "credential-set",
            Call::CounterRead | Call::CounterWrite => "signature-counter",
            Call::BlobRead | Call::BlobWrite => "large-blob-array",
        }
    }
}

const SLOTS: usize = 8;

/// The error a scheduled fault returns, of the kinds the file store does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// The storage could not be read or written (EIO, EACCES, ENOSPC).
    Io,
    /// What was read cannot be trusted: a record that fails authentication
    /// (`StoreError::Corrupt`), or for the credential set its membership
    /// metadata (`StoreError::CredentialSetUnavailable`).
    Corrupt,
}

fn error(call: Call, fault: Fault) -> StoreError {
    match (call, fault) {
        (Call::List | Call::Count | Call::Put | Call::Insert | Call::Delete, Fault::Corrupt) => {
            StoreError::CredentialSetUnavailable {
                object: call.object().into(),
                detail: "injected corrupt membership metadata".into(),
            }
        }
        (_, Fault::Corrupt) => StoreError::Corrupt {
            object: call.object().into(),
            reason: Corruption::Authentication,
        },
        (_, Fault::Io) => StoreError::Io {
            path: format!("fuzz-{}", call.object()).into(),
            source: std::io::Error::other("injected I/O failure"),
        },
    }
}

/// One store call, the fault it met (for a PIN-state publication, `Io` when
/// it was not published), and for a call on one credential its ID.
#[derive(Clone, Debug)]
pub(crate) struct Event {
    pub call: Call,
    pub fault: Option<Fault>,
    pub id: Vec<u8>,
}

struct State {
    store: MemoryStore,
    fault: Option<(u8, usize)>,
    /// Per fault slot: the fault and how many calls to let through first.
    faults: [Option<(Fault, usize)>; SLOTS],
    writes: Vec<Write>,
    events: Vec<Event>,
}

#[derive(Clone)]
pub(crate) struct HarnessStore(Arc<Mutex<State>>);

impl HarnessStore {
    pub fn new(store: MemoryStore) -> Self {
        Self(Arc::new(Mutex::new(State {
            store,
            fault: None,
            faults: [None; SLOTS],
            writes: Vec::new(),
            events: Vec::new(),
        })))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }

    pub fn schedule(&self, mode: u8, after: u8) {
        self.lock().fault = Some((mode % 4, usize::from(after % 4)));
    }

    /// Fail the call of `slot` that follows `after` more of them (modulo 4),
    /// replacing what the slot had scheduled.  The slots, modulo 8: PIN-state
    /// read; credential read; credential-set read (list, count); credential
    /// write (put, insert, delete); signature counter read; signature counter
    /// write; large-blob array read; large-blob array write.  The error is
    /// I/O, or for an odd `kind` the corruption the file store reports,
    /// except for the counter and large-blob writes, which only fail to
    /// write.  PIN-state publication has its own schedule ([`Self::schedule`]).
    pub fn schedule_fault(&self, slot: u8, kind: u8, after: u8) {
        let slot = usize::from(slot) % SLOTS;
        let fault = if kind % 2 == 1 && !matches!(slot, 5 | 7) {
            Fault::Corrupt
        } else {
            Fault::Io
        };
        self.lock().faults[slot] = Some((fault, usize::from(after % 4)));
    }

    pub fn take_writes(&self) -> Vec<Write> {
        std::mem::take(&mut self.lock().writes)
    }

    pub fn take_events(&self) -> Vec<Event> {
        std::mem::take(&mut self.lock().events)
    }

    /// Read the store as it is, without a fault or an event.
    pub fn inner<R>(&self, read: impl FnOnce(&MemoryStore) -> R) -> R {
        read(&self.lock().store)
    }
}

impl State {
    /// Record `call` and fail it if its slot's fault is due.
    fn enter(&mut self, call: Call, id: &[u8]) -> Result<(), StoreError> {
        let slot = call.slot();
        let fault = match &mut self.faults[slot] {
            Some((fault, 0)) => {
                let fault = *fault;
                self.faults[slot] = None;
                Some(fault)
            }
            Some((_, remaining)) => {
                *remaining -= 1;
                None
            }
            None => None,
        };
        self.events.push(Event {
            call,
            fault,
            id: id.to_vec(),
        });
        fault.map_or(Ok(()), |fault| Err(error(call, fault)))
    }

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
        self.events.push(Event {
            call: Call::PinWrite,
            fault: outcome.is_none().then_some(Fault::Io),
            id: Vec::new(),
        });
        outcome.ok_or(StoreError::Io {
            path: "fuzz-pin-state".into(),
            source: std::io::Error::other("injected pre-publication failure"),
        })
    }
}

impl CredentialStore for HarnessStore {
    fn get(&self, id: &[u8]) -> Result<Option<CredentialRecord>, StoreError> {
        let mut state = self.lock();
        state.enter(Call::Get, id)?;
        state.store.get(id)
    }
    fn put(&mut self, record: &CredentialRecord) -> Result<(), StoreError> {
        let mut state = self.lock();
        state.enter(Call::Put, &record.credential_id)?;
        state.store.put(record)
    }
    fn insert_or_replace_discoverable(
        &mut self,
        record: &CredentialRecord,
    ) -> Result<CredentialCommit, StoreError> {
        let mut state = self.lock();
        state.enter(Call::Insert, &record.credential_id)?;
        state.store.insert_or_replace_discoverable(record)
    }
    fn delete(&mut self, id: &[u8]) -> Result<bool, StoreError> {
        let mut state = self.lock();
        state.enter(Call::Delete, id)?;
        state.store.delete(id)
    }
    fn list(&self) -> Result<Vec<CredentialRecord>, StoreError> {
        let mut state = self.lock();
        state.enter(Call::List, &[])?;
        state.store.list()
    }
    fn count(&self) -> Result<usize, StoreError> {
        let mut state = self.lock();
        state.enter(Call::Count, &[])?;
        state.store.count()
    }
    fn max_credentials(&self) -> usize {
        self.lock().store.max_credentials()
    }
    fn clear(&mut self) -> Result<CommitDurability, StoreError> {
        let mut state = self.lock();
        let outcome = state.publication(&PinStateRecord::default())?;
        state.store.clear()?;
        Ok(outcome)
    }
    fn pin_state(&self) -> Result<Option<PinStateRecord>, StoreError> {
        let mut state = self.lock();
        state.enter(Call::PinRead, &[])?;
        state.store.pin_state()
    }
    fn set_pin_state(&mut self, record: &PinStateRecord) -> Result<CommitDurability, StoreError> {
        let mut state = self.lock();
        let outcome = state.publication(record)?;
        state.store.set_pin_state(record)?;
        Ok(outcome)
    }
    fn signature_counter(&self) -> Result<u32, StoreError> {
        let mut state = self.lock();
        state.enter(Call::CounterRead, &[])?;
        state.store.signature_counter()
    }
    fn set_signature_counter(&mut self, value: u32) -> Result<(), StoreError> {
        let mut state = self.lock();
        state.enter(Call::CounterWrite, &[])?;
        state.store.set_signature_counter(value)
    }
    fn large_blob_array(&self) -> Result<Vec<u8>, StoreError> {
        let mut state = self.lock();
        state.enter(Call::BlobRead, &[])?;
        state.store.large_blob_array()
    }
    fn set_large_blob_array(&mut self, array: &[u8]) -> Result<(), StoreError> {
        let mut state = self.lock();
        state.enter(Call::BlobWrite, &[])?;
        state.store.set_large_blob_array(array)
    }
    fn attestation(&self) -> Result<Option<AttestationRecord>, StoreError> {
        self.lock().store.attestation()
    }
    fn set_attestation(&mut self, record: &AttestationRecord) -> Result<(), StoreError> {
        self.lock().store.set_attestation(record)
    }
    fn seal_credential_id(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.lock().store.seal_credential_id(plaintext, ad)
    }
    fn open_credential_id(
        &self,
        sealed: &[u8],
        ad: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        self.lock().store.open_credential_id(sealed, ad)
    }
}
