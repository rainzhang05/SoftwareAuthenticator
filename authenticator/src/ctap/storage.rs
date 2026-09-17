//! Persistence through the [`CredentialStore`]: credentials, the persistent
//! part of the PIN state, and attestation material.
//!
//! Store errors are never mistaken for an empty store.  Reading or writing
//! fails the command with CTAP2_ERR_PROCESSING (CTAP2_ERR_KEY_STORE_FULL for
//! a full store), and corrupt individual credentials are skipped by
//! [`CredentialStore::list`] itself.

use super::pin::state::{PersistentPinState, PinState};
use super::CtapApp;
use crate::store::{
    AttestationRecord, CredentialRecord, CredentialStore, PinStateRecord, StoreError,
};

use rand_core::RngCore;
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
pub(super) fn load_pin_state(
    store: &dyn CredentialStore,
    rng: &mut dyn RngCore,
) -> (PinState, bool) {
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
fn unreadable_pin_state(rng: &mut dyn RngCore) -> PinState {
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
    /// Persist [`PersistentPinState`].  Called after every change to the PIN
    /// or to pinRetries, including the retry spent before a PIN is compared.
    /// A failed write is an error, so a PIN check fails closed instead of
    /// comparing a PIN whose spent retry was not saved.
    ///
    /// While the stored PIN state is unreadable nothing is written, so the
    /// fail-closed placeholder never replaces it.
    pub(super) fn save_persistent_pin_state(&mut self) -> Result<(), u8> {
        if !self.pin_state_writable {
            return Ok(());
        }
        let persistent = self.pin_state.persistent();
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
