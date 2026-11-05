//! Persistence through the [`CredentialStore`]: credentials, the persistent
//! part of the PIN state, the large-blob array and attestation material.
//!
//! Store errors are never mistaken for an empty store.  Reading or writing
//! fails the command with CTAP2_ERR_PROCESSING (CTAP2_ERR_KEY_STORE_FULL for
//! a full store), and corrupt individual credentials are skipped by
//! [`CredentialStore::list`] itself.  An error that reports damage to the
//! credential set is logged with the damaged file, what fails and what to do
//! ([`StoreError::damage_hint`]).
//! An unreadable large-blob array instead uses its initial value (§6.10.2).

use super::CtapApp;
use super::pin::state::{PersistentPinState, PinState};
use crate::store::{
    AttestationRecord, CommitDurability, CredentialRecord, CredentialStore, DirectoryFlush,
    PinStateRecord, StoreError,
};

use rand_core::Rng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::ctap::constants::*;

/// The CTAP status for a failed store operation, logged with `action`.
pub(super) fn store_status(action: &str, err: StoreError) -> u8 {
    match err {
        StoreError::Full { max } => {
            log::warn!("cannot {action}: the credential store is full ({max} credentials)");
            CTAP2_ERR_KEY_STORE_FULL
        }
        err => {
            log::error!("cannot {action}: {}", explained(&err));
            CTAP2_ERR_PROCESSING
        }
    }
}

/// `err` as the log says it: followed, if it reports damage to the
/// credential set, by the damaged file, what fails and what to do.
pub(super) fn explained(err: &StoreError) -> String {
    match err.damage_hint() {
        Some(hint) => format!("{err}. {hint}"),
        None => err.to_string(),
    }
}

/// What the engine has read of the PIN state in its store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StoredPinState {
    /// Read, or never written: the live persistent state is the stored one,
    /// and changes to it are written back.
    Read,
    /// An I/O error kept it from being read at start-up, or after a failed
    /// reset (see [`CtapApp::reconcile_persistent_authority`]).  The live
    /// state is closed and nothing is written; the next command that depends
    /// on it reads it again, through [`CtapApp::refresh_persistent_authority`].
    Unread,
    /// It cannot be trusted (see `closes_authority`).  The live state is
    /// closed, and nothing is read or written until reset.
    Unreadable,
}

/// The PIN state the engine starts with, and what it read of the stored one.
///
/// Only [`PersistentPinState`], the PIN and UV policy, is read from the
/// store.  The consecutive-mismatch lockout is volatile (a restart is this
/// authenticator's power cycle), so `consecutive_failures` and
/// `pin_auth_blocked` in [`PinStateRecord`] are never read back.
///
/// A PIN state that cannot be read fails closed: the PIN is treated as set,
/// with a random hash nobody knows, and blocked with no retries left, so PIN
/// checks are refused with CTAP2_ERR_PIN_BLOCKED before any comparison and
/// always-UV conservatively remains required.  Nothing is written back over
/// the stored record.  After an I/O error the state is only
/// [`StoredPinState::Unread`]: the commands that depend on it read it again
/// first.  After any other error only reset recovers.
pub(super) fn load_pin_state(
    store: &dyn CredentialStore,
    rng: &mut dyn Rng,
) -> (PinState, StoredPinState) {
    match store.pin_state() {
        Ok(Some(record)) => (
            PinState::from_persistent(PersistentPinState {
                pin_hash: record.pin_hash,
                pin_retries: record.pin_retries,
                min_pin_length: record.min_pin_length,
                min_pin_length_rp_ids: record.min_pin_length_rp_ids.clone(),
                force_pin_change: record.force_pin_change,
                pin_code_point_length: record.pin_code_point_length,
                always_uv: record.always_uv,
                pin_complexity_policy: record.pin_complexity_policy,
                persistent_tokens: record.persistent_tokens.clone(),
            }),
            StoredPinState::Read,
        ),
        Ok(None) => (PinState::new(), StoredPinState::Read),
        Err(err) if closes_authority(&err) => {
            log::error!(
                "the stored PIN state cannot be read ({err}); treating the PIN as set and \
                 blocked until the authenticator is reset"
            );
            (unreadable_pin_state(rng), StoredPinState::Unreadable)
        }
        Err(err) => {
            log::error!(
                "the stored PIN state could not be read ({err}); treating the PIN as set and \
                 blocked until it is read"
            );
            (unreadable_pin_state(rng), StoredPinState::Unread)
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
        always_uv: true,
        min_pin_length_rp_ids: Vec::new(),
        persistent_tokens: [None, None],
        ..PersistentPinState::default()
    });
    hash.zeroize();
    state
}

/// Whether `err`, from reading the PIN state at start-up or later, condemns
/// the stored authority and not just this read of it, so that the engine
/// closes authority until reset.  Every variant is decided here, so that a
/// new one has to be.
fn closes_authority(err: &StoreError) -> bool {
    match err {
        // The storage could not be read (EIO, EMFILE, EACCES).  That says
        // nothing about the record, which the next read can find intact;
        // closing would report a blocked PIN that only a restart or a reset
        // clears.
        StoreError::Io { .. } => false,
        // The record exists but fails authentication or decoding, or its key
        // is unusable or missing although data encrypted under it exists:
        // what it holds cannot be known.  This is what closing is for.
        StoreError::Corrupt { .. } | StoreError::KeyUnavailable { .. } => true,
        // The stores never report these from a PIN-state read; they belong to
        // membership metadata, inserts, write validation and key generation.
        // A store that does is broken, so they close authority as before.
        StoreError::CredentialSetUnavailable { .. }
        | StoreError::Full { .. }
        | StoreError::InvalidRecord(_)
        | StoreError::Random => true,
    }
}

impl CtapApp<'_> {
    /// Re-read authority before persistent access or PIN verification. In particular,
    /// a failed reset can have published a new key while leaving old ciphertext.
    ///
    /// A read that fails with an I/O error returns CTAP2_ERR_PROCESSING and
    /// changes nothing: the live authority and its tokens stay as they are,
    /// so the next command reads again.  A record that is missing although a
    /// PIN or token exists, that cannot be authenticated or decoded, or whose
    /// key is unusable or missing closes authority until reset, as
    /// [`load_pin_state`] does.  A PIN state start-up could not read is read
    /// here as start-up reads it.
    pub(super) fn refresh_persistent_authority(&mut self) -> Result<(), u8> {
        match self.stored_pin_state {
            StoredPinState::Read => {}
            StoredPinState::Unread => return self.read_unread_pin_state(),
            StoredPinState::Unreadable => return Ok(()),
        }
        let loaded = self.store.pin_state();
        let record = match loaded {
            Ok(Some(record)) => record,
            // A missing authority is allowed only before a PIN or token exists.
            Ok(None)
                if self.pin_state.persistent().pin_hash.is_none()
                    && self
                        .pin_state
                        .persistent()
                        .persistent_tokens
                        .iter()
                        .all(Option::is_none) =>
            {
                return Ok(());
            }
            Err(err) if !closes_authority(&err) => {
                return Err(store_status("read persistent authority", err));
            }
            other => {
                let mut closed = self.pin_state.persistent().clone();
                closed.persistent_tokens = [None, None];
                closed.pin_retries = 0;
                closed.always_uv = true;
                self.pin_state.adopt_persistent(closed);
                self.pin_state.invalidate_pin_uv_auth_tokens();
                self.cred_mgmt_state.clear();
                self.stored_pin_state = StoredPinState::Unreadable;
                if let Err(err) = other {
                    return Err(store_status("read persistent authority", err));
                }
                return Err(CTAP2_ERR_PROCESSING);
            }
        };
        let current = self.pin_state.persistent();
        let hash_changed = match (&current.pin_hash, &record.pin_hash) {
            (Some(a), Some(b)) => !bool::from(a.ct_eq(b)),
            (None, None) => false,
            _ => true,
        };
        let changed_pin = hash_changed
            || current.min_pin_length != record.min_pin_length
            || current.min_pin_length_rp_ids != record.min_pin_length_rp_ids
            || current.force_pin_change != record.force_pin_change
            || current.pin_code_point_length != record.pin_code_point_length
            || current.always_uv != record.always_uv
            || current.pin_complexity_policy != record.pin_complexity_policy;
        if changed_pin || current.persistent_tokens != record.persistent_tokens {
            let persistent = PersistentPinState {
                pin_hash: record.pin_hash,
                pin_retries: record.pin_retries,
                min_pin_length: record.min_pin_length,
                min_pin_length_rp_ids: record.min_pin_length_rp_ids.clone(),
                force_pin_change: record.force_pin_change,
                pin_code_point_length: record.pin_code_point_length,
                always_uv: record.always_uv,
                pin_complexity_policy: record.pin_complexity_policy,
                persistent_tokens: record.persistent_tokens.clone(),
            };
            if changed_pin {
                self.pin_state.invalidate_pin_uv_auth_tokens();
            }
            self.pin_state.adopt_persistent(persistent);
            self.cred_mgmt_state.clear();
        }
        Ok(())
    }

    /// Re-read authority after a failed reset, which can have published a new
    /// key or the default PIN state before failing (see
    /// [`CredentialStore::clear`]); every other PIN-state write that fails has
    /// published nothing ([`CredentialStore::set_pin_state`]).  As
    /// [`Self::refresh_persistent_authority`], except that an I/O error does
    /// not keep the live authority, which may now be wider than the stored
    /// one: it is closed as at start-up, and the next command that depends on
    /// it reads it again.
    pub(super) fn reconcile_persistent_authority(&mut self) {
        // Only an I/O error fails a refresh and leaves the state `Read`.
        if self.refresh_persistent_authority().is_err()
            && self.stored_pin_state == StoredPinState::Read
        {
            let closed = unreadable_pin_state(&mut *self.rng);
            self.pin_state.adopt_persistent(closed.persistent().clone());
            self.pin_state.invalidate_pin_uv_auth_tokens();
            self.cred_mgmt_state.clear();
            self.stored_pin_state = StoredPinState::Unread;
        }
    }

    /// Read the PIN state an I/O error kept from being read, as start-up reads
    /// it, and adopt its persistent part.  The clock, the key agreement keys
    /// and the token state are kept; no token is issued while the state is
    /// unread.  Fails with CTAP2_ERR_PROCESSING, leaving the live state
    /// closed, while it cannot be read.
    fn read_unread_pin_state(&mut self) -> Result<(), u8> {
        let (loaded, stored) = load_pin_state(&*self.store, &mut *self.rng);
        self.stored_pin_state = stored;
        match stored {
            StoredPinState::Read => {
                self.pin_state.adopt_persistent(loaded.persistent().clone());
                self.pin_state.invalidate_pin_uv_auth_tokens();
                self.cred_mgmt_state.clear();
                Ok(())
            }
            StoredPinState::Unread | StoredPinState::Unreadable => Err(CTAP2_ERR_PROCESSING),
        }
    }

    /// Read the PIN state first if it is unread, before a command that answers
    /// from it without rereading it.  Does nothing once it is read.
    pub(super) fn read_pin_state_if_unread(&mut self) -> Result<(), u8> {
        if self.stored_pin_state == StoredPinState::Unread {
            self.refresh_persistent_authority()
        } else {
            Ok(())
        }
    }

    /// Refuse a failed or repeating random source before publishing authority.
    pub(super) fn fresh_token_secret(
        &mut self,
        forbidden: &[&[u8; 32]],
        persistent: bool,
    ) -> Result<Zeroizing<[u8; 32]>, u8> {
        for _ in 0..8 {
            let candidate = Zeroizing::new(self.random_array::<32>());
            if candidate.iter().any(|byte| *byte != 0)
                && !forbidden
                    .iter()
                    .any(|old| bool::from(old.ct_eq(&*candidate)))
                && (!persistent || !self.pin_state.transient_secret_matches(&candidate))
            {
                return Ok(candidate);
            }
        }
        Err(CTAP2_ERR_PROCESSING)
    }

    /// Stage all rotation randomness before publishing a new PIN/policy.
    pub(super) fn rotate_persistent_tokens(
        &mut self,
        persistent: &mut PersistentPinState,
    ) -> Result<(), u8> {
        let preceding = persistent.persistent_tokens.clone();
        let mut rotated = [None, None];
        for index in 0..2 {
            let forbidden: Vec<_> = preceding
                .iter()
                .chain(rotated.iter())
                .flatten()
                .map(|token: &crate::store::PersistentTokenRecord| &token.secret)
                .collect();
            let secret = self.fresh_token_secret(&forbidden, true)?;
            rotated[index] = Some(crate::store::PersistentTokenRecord {
                secret: *secret,
                granted: false,
            });
        }
        persistent.persistent_tokens = rotated;
        Ok(())
    }

    /// Persist the next count before signing. Sealed credentials share the
    /// global counter; stored ones count individually. Neither wraps.
    pub(super) fn advance_signature_counter(
        &mut self,
        credential: &mut CredentialRecord,
    ) -> Result<(), u8> {
        if super::credential_id::is_sealed(&credential.credential_id) {
            let count = self
                .store
                .signature_counter()
                .map_err(|err| store_status("read the global signature counter", err))?
                .saturating_add(1);
            self.store
                .set_signature_counter(count)
                .map_err(|err| store_status("save the global signature counter", err))?;
            credential.sign_count = count;
        } else {
            credential.sign_count = credential.sign_count.saturating_add(1);
            self.store
                .put(credential)
                .map_err(|err| store_status("save the signature counter", err))?;
        }
        Ok(())
    }

    /// Persist the live [`PersistentPinState`], one the engine has already
    /// adopted, as after a PIN mismatch.  A state it adopts only once stored,
    /// such as the retry spent before a PIN is compared, is written with
    /// [`Self::save_pin_state`] instead.
    /// Publication and durability are returned separately: settings may adopt
    /// any published state, but verification requires Flushed or intentional
    /// Volatile persistence before comparison and authorization.
    ///
    /// While the stored PIN state is unread or unreadable nothing is written,
    /// so the fail-closed placeholder never replaces it.
    pub(super) fn save_persistent_pin_state(&mut self) -> Result<CommitDurability, u8> {
        let persistent = self.pin_state.persistent().clone();
        self.save_pin_state(&persistent)
    }

    /// Persist `persistent`, which may be a PIN state the engine only adopts
    /// once it is stored.  Otherwise as [`Self::save_persistent_pin_state`].
    pub(super) fn save_pin_state(
        &mut self,
        persistent: &PersistentPinState,
    ) -> Result<CommitDurability, u8> {
        if self.stored_pin_state != StoredPinState::Read {
            return Err(CTAP2_ERR_PROCESSING);
        }
        let record = PinStateRecord {
            pin_hash: persistent.pin_hash,
            pin_retries: persistent.pin_retries,
            min_pin_length: persistent.min_pin_length,
            min_pin_length_rp_ids: persistent.min_pin_length_rp_ids.clone(),
            force_pin_change: persistent.force_pin_change,
            pin_code_point_length: persistent.pin_code_point_length,
            always_uv: persistent.always_uv,
            pin_complexity_policy: persistent.pin_complexity_policy,
            persistent_tokens: persistent.persistent_tokens.clone(),
            ..PinStateRecord::default()
        };
        self.store
            .set_pin_state(&record)
            .map_err(|err| store_status("save the PIN state", err))
    }

    /// The error with which the store's filesystem refuses to flush the
    /// directory the PIN state is published in, if it does not support
    /// directory flushes ([`CredentialStore::directory_flush`]).  There no
    /// PIN-state write is ever confirmed, so a PIN could never be checked:
    /// setPIN and every PIN check refuse before they write anything.
    ///
    /// The store is asked at the first PIN operation that needs to know, and
    /// its answer is kept for the engine's life, so that a PIN check costs no
    /// flush of its own; a restart asks again.  A flush that merely failed
    /// shows nothing and is not kept: the operation goes on, and the next one
    /// asks again.
    pub(super) fn unsupported_directory_flush(&mut self) -> Option<&StoreError> {
        if self.directory_flush.is_none() {
            match self.store.directory_flush() {
                DirectoryFlush::Failed(_) => return None,
                known => self.directory_flush = Some(known),
            }
        }
        match &self.directory_flush {
            Some(DirectoryFlush::Unsupported(err)) => Some(err),
            _ => None,
        }
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
                log::warn!("skipping a corrupt credential: {}", explained(&err));
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
