//! Persistence through the [`CredentialStore`]: credentials, the persistent
//! part of the PIN state, and attestation material.
//!
//! Store errors are never mistaken for an empty store.  Reading or writing
//! fails the command with CTAP2_ERR_PROCESSING (CTAP2_ERR_KEY_STORE_FULL for
//! a full store), and corrupt individual credentials are skipped by
//! [`CredentialStore::list`] itself.

use super::CtapApp;
use super::pin::state::{PersistentPinState, PinState};
use crate::store::{
    AttestationRecord, CredentialRecord, CredentialStore, PinStateRecord, StoreError,
};

use rand_core::Rng;
use zeroize::Zeroize;

use crate::ctap::constants::*;

/// The CTAP status for a failed store operation, logged with `action`.
pub(super) fn store_status(action: &str, err: StoreError) -> u8 {
    match err {
        StoreError::Full { max } => {
            log::warn!("cannot {action}: the credential store is full ({max} credentials)");
            CTAP2_ERR_KEY_STORE_FULL
        }
        err => {
            log::error!("cannot {action}: {err}");
            CTAP2_ERR_PROCESSING
        }
    }
}

/// The PIN state the engine starts with, and whether it may be written back.
///
/// Only [`PersistentPinState`], the PIN hash and pinRetries, is read from the
/// store.  The consecutive-mismatch lockout is volatile (a restart is this
/// authenticator's power cycle), so `consecutive_failures` and
/// `pin_auth_blocked` in [`PinStateRecord`] are never read back.
///
/// A PIN state that cannot be read fails closed: the PIN is treated as set,
/// with a random hash nobody knows, and blocked with no retries left, so PIN
/// checks are refused with CTAP2_ERR_PIN_BLOCKED before any comparison and
/// only authenticatorReset recovers.  Nothing is written back over the
/// unreadable record until then.
pub(super) fn load_pin_state(store: &dyn CredentialStore, rng: &mut dyn Rng) -> (PinState, bool) {
    match store.pin_state() {
        Ok(Some(record)) => (
            PinState::from_persistent(PersistentPinState {
                pin_hash: record.pin_hash,
                pin_retries: record.pin_retries,
            }),
            true,
        ),
        Ok(None) => (PinState::new(), true),
        Err(err) => {
            log::error!(
                "the stored PIN state cannot be read ({err}); treating the PIN as set and \
                 blocked until the authenticator is reset"
            );
            (unreadable_pin_state(rng), false)
        }
    }
}

/// Set and blocked: no retries left, and a random PIN hash.  The platform
/// supplies the PIN hash itself (pinHashEnc), so a fixed placeholder could be
/// sent directly; a random one cannot be guessed.
fn unreadable_pin_state(rng: &mut dyn Rng) -> PinState {
    let mut hash = [0u8; 16];
    rng.fill_bytes(&mut hash);
    let state = PinState::from_persistent(PersistentPinState {
        pin_hash: Some(hash),
        pin_retries: 0,
    });
    hash.zeroize();
    state
}

impl CtapApp<'_> {
    /// A fresh credential ID that records whether the credential is
    /// discoverable; see [`is_discoverable`].
    pub(super) fn new_credential_id(&mut self, discoverable: bool) -> Vec<u8> {
        let mut credential_id = Vec::with_capacity(CREDENTIAL_ID_LENGTH);
        credential_id.push(if discoverable {
            DISCOVERABLE_MARKER
        } else {
            NON_DISCOVERABLE_MARKER
        });
        credential_id.extend_from_slice(&self.random_array::<32>());
        credential_id
    }

    /// Persist [`PersistentPinState`].  Called after every change to the PIN
    /// or to pinRetries, including the retry spent before a PIN is compared.
    /// A failed write is an error, so a PIN check fails closed instead of
    /// comparing a PIN whose spent retry was not saved.
    ///
    /// While the stored PIN state is unreadable nothing is written, so the
    /// fail-closed placeholder never replaces it.
    pub(super) fn save_persistent_pin_state(&mut self) -> Result<(), u8> {
        let persistent = self.pin_state.persistent().clone();
        self.save_pin_state(&persistent)
    }

    /// Persist `persistent`, which may be a PIN state the engine only adopts
    /// once it is stored.  Otherwise as [`Self::save_persistent_pin_state`].
    pub(super) fn save_pin_state(&mut self, persistent: &PersistentPinState) -> Result<(), u8> {
        if !self.pin_state_writable {
            return Ok(());
        }
        let record = PinStateRecord {
            pin_hash: persistent.pin_hash,
            pin_retries: persistent.pin_retries,
            ..PinStateRecord::default()
        };
        self.store
            .set_pin_state(&record)
            .map_err(|err| store_status("save the PIN state", err))
    }

    /// Every readable credential, most recently created first.
    pub(super) fn stored_credentials(&self) -> Result<Vec<CredentialRecord>, u8> {
        self.store
            .list()
            .map_err(|err| store_status("list credentials", err))
    }

    /// The credential with this ID, or `None` if there is none.  A corrupt
    /// credential is logged and treated like a missing one, exactly as
    /// [`CredentialStore::list`] skips it; any other failure is an error.
    pub(super) fn stored_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<CredentialRecord>, u8> {
        match self.store.get(credential_id) {
            Ok(record) => Ok(record),
            Err(err @ StoreError::Corrupt { .. }) => {
                log::warn!("skipping a corrupt credential: {err}");
                Ok(None)
            }
            Err(err) => Err(store_status("read a credential", err)),
        }
    }

    /// The attestation key and certificate chain, if provisioned.
    ///
    /// An unreadable attestation record is logged and treated as absent, so
    /// registration falls back to self attestation instead of failing until
    /// the record is repaired.  The attestation key is a per-installation key
    /// with a self-signed certificate, so the fallback costs no trust.
    pub(super) fn attestation_record(&self) -> Option<AttestationRecord> {
        match self.store.attestation() {
            Ok(record) => record,
            Err(err) => {
                log::error!(
                    "the attestation record cannot be read ({err}); using self attestation"
                );
                None
            }
        }
    }
}

/// The length of the credential IDs this engine creates: a marker byte and
/// 32 random bytes.
pub(super) const CREDENTIAL_ID_LENGTH: usize = 33;

/// The first byte of the ID of a credential created with "rk" true.
const DISCOVERABLE_MARKER: u8 = 0x01;

/// The first byte of the ID of a credential created with "rk" false.
const NON_DISCOVERABLE_MARKER: u8 = 0x00;

/// Whether a credential is discoverable, which its ID records.
///
/// CTAP 2.3 §6.1.2 step 18: "Otherwise, if the "rk" option is false: the
/// authenticator MUST create a non-discoverable credential", one whose
/// "credential IDs MUST be supplied by the Relying Party in
/// authenticatorGetAssertion's allowList parameter in order for the
/// authenticator to discover and employ them" (§6.1.3).  The same section
/// allows keeping state for such a credential: "An authenticator may choose
/// to keep state, such as the private key, whether a credential is
/// discoverable or not".  So every credential is a stored record, and the
/// credential ID says which kind it is, which needs no field in the stored
/// record and so no change to the store's format:
///
/// * IDs this engine creates are [`CREDENTIAL_ID_LENGTH`] bytes: a marker byte
///   ([`DISCOVERABLE_MARKER`] or [`NON_DISCOVERABLE_MARKER`]) and 32 random
///   bytes.
/// * Any other ID, including the 32 random bytes of credentials created
///   before non-discoverable credentials existed, all of which were
///   discoverable, is discoverable.
///
/// The marker cannot be changed from outside: the store authenticates each
/// record together with its credential ID, and a credential is only ever
/// found by its exact ID.
pub(super) fn is_discoverable(credential_id: &[u8]) -> bool {
    !(credential_id.len() == CREDENTIAL_ID_LENGTH && credential_id[0] == NON_DISCOVERABLE_MARKER)
}
