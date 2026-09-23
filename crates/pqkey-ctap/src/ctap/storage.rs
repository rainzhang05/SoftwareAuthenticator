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
    AttestationRecord, CredentialRecord, CredentialStore, PinStateRecord, PrivateKeyMaterial,
    SEALED_ID_OVERHEAD, StoreError, validate_credential,
};
use crate::{CoseAlg, hkdf_sha256};

use rand_core::Rng;
use sha2::{Digest, Sha256};
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
    /// A fresh ID for a discoverable credential; see [`is_discoverable`].
    pub(super) fn new_credential_id(&mut self) -> Vec<u8> {
        let mut credential_id = Vec::with_capacity(CREDENTIAL_ID_LENGTH);
        credential_id.push(DISCOVERABLE_MARKER);
        credential_id.extend_from_slice(&self.random_array::<32>());
        credential_id
    }

    /// The ID of a new non-discoverable credential: the credential itself,
    /// sealed by the store and bound to its relying party, so that nothing
    /// needs to be stored.  See [`is_discoverable`].
    pub(super) fn seal_credential(&mut self, record: &CredentialRecord) -> Result<Vec<u8>, u8> {
        let alg = i8::try_from(record.alg as i32).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut plaintext = Zeroizing::new([0u8; SEALED_PLAINTEXT_LENGTH]);
        plaintext[0] = alg as u8;
        plaintext[1] = record.cred_protect;
        plaintext[2..].copy_from_slice(private_key_bytes(&record.private_key));
        let sealed = self
            .store
            .seal_credential_id(&plaintext[..], &sealed_associated_data(&record.rp_id))
            .map_err(|err| store_status("seal a credential ID", err))?;
        if sealed.len() != SEALED_ID_LENGTH - 1 {
            log::error!("the store sealed a credential ID of the wrong length");
            return Err(CTAP2_ERR_PROCESSING);
        }
        let mut credential_id = Vec::with_capacity(SEALED_ID_LENGTH);
        credential_id.push(SEALED_MARKER);
        credential_id.extend_from_slice(&sealed);
        Ok(credential_id)
    }

    /// The credential `credential_id` names for relying party `rp_id`: a
    /// stored one, or the non-discoverable one a sealed ID carries.  `None` if
    /// there is none, if it belongs to another relying party, or if a sealed
    /// ID was not made for `rp_id` since the last reset.
    pub(super) fn credential_for_rp(
        &self,
        credential_id: &[u8],
        rp_id: &str,
    ) -> Result<Option<CredentialRecord>, u8> {
        if !is_sealed(credential_id) {
            return Ok(self
                .stored_credential(credential_id)?
                .filter(|credential| credential.rp_id == rp_id));
        }
        let opened = self
            .store
            .open_credential_id(&credential_id[1..], &sealed_associated_data(rp_id))
            .map_err(|err| store_status("open a credential ID", err))?;
        let Some(plaintext) = opened else {
            return Ok(None);
        };
        let credential = sealed_credential(credential_id, rp_id, &plaintext);
        if credential.is_none() {
            // Authentic, so sealed by this store, and yet not a credential.
            log::error!("a sealed credential ID holds no usable credential");
        }
        Ok(credential)
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

/// The length of the IDs of stored credentials this engine creates: a marker
/// byte and 32 random bytes.
pub(super) const CREDENTIAL_ID_LENGTH: usize = 33;

/// The first byte of the ID of a credential created with "rk" true.
const DISCOVERABLE_MARKER: u8 = 0x01;

/// The first byte of the ID of a stored credential created with "rk" false,
/// before non-discoverable credentials were sealed into their IDs.
const NON_DISCOVERABLE_MARKER: u8 = 0x00;

/// The first byte of a sealed credential ID.
const SEALED_MARKER: u8 = 0x02;

/// What a sealed credential ID holds: the COSE algorithm as a signed byte, the
/// credProtect level, and the 32-byte private key (a P-256 scalar or an
/// ML-DSA seed).
const SEALED_PLAINTEXT_LENGTH: usize = 34;

/// The length of a sealed credential ID: [`SEALED_MARKER`], then the sealed
/// plaintext.
pub(super) const SEALED_ID_LENGTH: usize = 1 + SEALED_ID_OVERHEAD + SEALED_PLAINTEXT_LENGTH;

// Platforms leave out allowList and excludeList entries longer than the
// maxCredentialIdLength getInfo reports.
const _: () = assert!(SEALED_ID_LENGTH as u64 <= super::get_info::MAX_CREDENTIAL_ID_LENGTH);

/// Bound into every sealed credential ID, followed by the SHA-256 hash of the
/// relying party ID.
const SEALED_ID_CONTEXT: &[u8] = b"pqkey/v1/sealed-credential-id";

/// Whether `credential_id` has the form of a sealed credential ID.
pub(super) fn is_sealed(credential_id: &[u8]) -> bool {
    credential_id.len() == SEALED_ID_LENGTH && credential_id[0] == SEALED_MARKER
}

fn sealed_associated_data(rp_id: &str) -> Vec<u8> {
    let mut associated_data = Vec::with_capacity(SEALED_ID_CONTEXT.len() + 32);
    associated_data.extend_from_slice(SEALED_ID_CONTEXT);
    associated_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    associated_data
}

fn private_key_bytes(private_key: &PrivateKeyMaterial) -> &[u8; 32] {
    match private_key {
        PrivateKeyMaterial::Es256 { scalar } => scalar,
        PrivateKeyMaterial::MlDsa { seed } => seed,
    }
}

/// Derive a sealed credential's hmac-secret CredRandom values from its private
/// key: nothing about the credential is stored, yet they must be the same at
/// every assertion (CTAP 2.3 §12.7).  HKDF keeps them independent of the key
/// and of each other.
pub(super) fn derive_sealed_cred_randoms(record: &mut CredentialRecord) -> Result<(), u8> {
    let key = private_key_bytes(&record.private_key);
    hkdf_sha256(
        key,
        b"pqkey/v1/sealed-credential/cred-random-with-uv",
        &mut record.cred_random_with_uv,
    )
    .and_then(|()| {
        hkdf_sha256(
            key,
            b"pqkey/v1/sealed-credential/cred-random-without-uv",
            &mut record.cred_random_without_uv,
        )
    })
    .map_err(|_| CTAP2_ERR_PROCESSING)
}

/// The credential a sealed ID's `plaintext` describes, or `None` if it does
/// not describe one.
fn sealed_credential(
    credential_id: &[u8],
    rp_id: &str,
    plaintext: &[u8],
) -> Option<CredentialRecord> {
    let [alg, cred_protect, key @ ..] = plaintext else {
        return None;
    };
    if key.len() != 32 {
        return None;
    }
    let alg = CoseAlg::try_from(i32::from(*alg as i8)).ok()?;
    let mut private_key = match alg {
        CoseAlg::ES256 => PrivateKeyMaterial::Es256 { scalar: [0; 32] },
        CoseAlg::MLDSA44 | CoseAlg::MLDSA65 | CoseAlg::MLDSA87 => {
            PrivateKeyMaterial::MlDsa { seed: [0; 32] }
        }
    };
    match &mut private_key {
        PrivateKeyMaterial::Es256 { scalar: bytes } | PrivateKeyMaterial::MlDsa { seed: bytes } => {
            bytes.copy_from_slice(key);
        }
    }
    let mut credential = CredentialRecord {
        credential_id: credential_id.to_vec(),
        rp_id: rp_id.to_owned(),
        user_id: Vec::new(),
        user_name: None,
        user_display_name: None,
        alg,
        private_key,
        cred_random_with_uv: [0; 32],
        cred_random_without_uv: [0; 32],
        cred_protect: *cred_protect,
        sign_count: 0,
        created_at: 0,
    };
    derive_sealed_cred_randoms(&mut credential).ok()?;
    validate_credential(&credential).ok()?;
    Some(credential)
}

/// Whether a credential is discoverable, which its ID records.
///
/// CTAP 2.3 §6.1.2 step 18: "Otherwise, if the "rk" option is false: the
/// authenticator MUST create a non-discoverable credential", one whose
/// "credential IDs MUST be supplied by the Relying Party in
/// authenticatorGetAssertion's allowList parameter in order for the
/// authenticator to discover and employ them" (§6.1.3).  Such a credential
/// needs no state on the authenticator, so its ID carries it:
///
/// * A discoverable credential is a stored record with a
///   [`CREDENTIAL_ID_LENGTH`]-byte ID, [`DISCOVERABLE_MARKER`] and 32 random
///   bytes.
/// * A non-discoverable credential is not stored.  Its ID is
///   [`SEALED_ID_LENGTH`] bytes: [`SEALED_MARKER`], then its algorithm,
///   credProtect level and private key, sealed by the store under a key that
///   a reset replaces and bound to the relying party.  It has no signature
///   counter (it reports 0), and its hmac-secret CredRandom values derive from
///   its key.
/// * Non-discoverable credentials made before they were sealed are stored
///   records whose ID is [`NON_DISCOVERABLE_MARKER`] and 32 random bytes.
/// * Any other stored ID, such as the 32 random bytes of credentials created
///   before non-discoverable credentials existed, all of which were
///   discoverable, is discoverable.
///
/// The ID of a stored credential cannot be changed from outside: the store
/// authenticates each record together with its credential ID, and a
/// credential is only ever found by its exact ID.
pub(super) fn is_discoverable(credential_id: &[u8]) -> bool {
    !is_sealed(credential_id)
        && !(credential_id.len() == CREDENTIAL_ID_LENGTH
            && credential_id[0] == NON_DISCOVERABLE_MARKER)
}
