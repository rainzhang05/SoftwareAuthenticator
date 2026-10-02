//! The credential IDs this engine creates and reads: the ID of a
//! discoverable credential names a stored record, and a non-discoverable
//! credential is sealed into its own ID; see [`is_discoverable`].

use super::CtapApp;
use super::storage::store_status;
use crate::CoseAlg;
use crate::crypto::hkdf::hkdf_sha256;
use crate::store::{CredentialRecord, PrivateKeyMaterial, SEALED_ID_OVERHEAD, validate_credential};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ctap::constants::*;

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
    /// needs to be stored.  A fresh random seed for its hmac-secret
    /// CredRandom values goes into the ID too, and `record` gets the values
    /// it derives.  See [`is_discoverable`].
    pub(super) fn seal_credential(&mut self, record: &mut CredentialRecord) -> Result<Vec<u8>, u8> {
        let alg = i8::try_from(record.alg.identifier()).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let seed = Zeroizing::new(self.random_array::<32>());
        derive_sealed_cred_randoms(record, &seed)?;
        let mut plaintext = Zeroizing::new([0u8; SEALED_PLAINTEXT_LENGTH]);
        plaintext[0] = alg as u8;
        plaintext[1] = record.cred_protect;
        let key: &[u8; SEALED_KEY_LENGTH] = record.private_key.as_bytes();
        plaintext[2..2 + SEALED_KEY_LENGTH].copy_from_slice(key);
        plaintext[2 + SEALED_KEY_LENGTH..].copy_from_slice(&seed[..]);
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
/// credProtect level, the 32-byte private key material (a P-256 scalar or a
/// seed), and the 32-byte random seed of its hmac-secret CredRandom values
/// (see [`derive_sealed_cred_randoms`]).
const SEALED_PLAINTEXT_LENGTH: usize = 2 + SEALED_KEY_LENGTH + 32;

/// The length of a sealed ID's private key field, which holds the key
/// material of any kind.
const SEALED_KEY_LENGTH: usize = 32;

// Every algorithm of the table fits a sealed ID.  Its identifier is the
// plaintext's first byte, a signed one.  Its key material fits the key field
// by type: `PrivateKeyMaterial::as_bytes` is `[u8; SEALED_KEY_LENGTH]` for
// every kind, or `seal_credential` does not compile.
const _: () = {
    let mut i = 0;
    while i < CoseAlg::ALL.len() {
        let identifier = CoseAlg::ALL[i].identifier();
        assert!(
            identifier >= i8::MIN as i32 && identifier <= i8::MAX as i32,
            "a COSE algorithm identifier does not fit a sealed credential ID"
        );
        i += 1;
    }
};

/// The length of a sealed credential ID: [`SEALED_MARKER`], then the sealed
/// plaintext.
pub(super) const SEALED_ID_LENGTH: usize = 1 + SEALED_ID_OVERHEAD + SEALED_PLAINTEXT_LENGTH;

// Platforms leave out allowList and excludeList entries longer than the
// maxCredentialIdLength getInfo reports.
const _: () = assert!(SEALED_ID_LENGTH as u64 <= super::get_info::MAX_CREDENTIAL_ID_LENGTH);

/// Bound into every sealed credential ID, followed by the SHA-256 hash of the
/// relying party ID.
/// Version 2 added the CredRandom seed; version 1 IDs, 75 bytes long, are no
/// longer opened.
const SEALED_ID_CONTEXT: &[u8] = b"pqkey/v2/sealed-credential-id";

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

/// Derive a sealed credential's hmac-secret CredRandom values from the random
/// seed sealed into its ID.  "The authenticator generates two random 32-byte
/// values (called CredRandomWithUV and CredRandomWithoutUV) and associates
/// them with the credential." (CTAP 2.3 §12.7)  Nothing about a sealed
/// credential is stored and a credential ID may hold at most 128 bytes, so
/// one random 32-byte seed is sealed instead of the two values, and HKDF
/// expands it into two independent values, the same at every assertion.
/// They never derive from the signing key, which is used for nothing but
/// signing (FIPS 204: "digital signature key pairs shall not be used for
/// other purposes").
pub(super) fn derive_sealed_cred_randoms(
    record: &mut CredentialRecord,
    seed: &[u8; 32],
) -> Result<(), u8> {
    hkdf_sha256(
        seed,
        b"pqkey/v2/sealed-credential/cred-random-with-uv",
        &mut record.cred_random_with_uv,
    )
    .and_then(|()| {
        hkdf_sha256(
            seed,
            b"pqkey/v2/sealed-credential/cred-random-without-uv",
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
    let [alg, cred_protect, rest @ ..] = plaintext else {
        return None;
    };
    if rest.len() != SEALED_KEY_LENGTH + 32 {
        return None;
    }
    let (key, seed) = rest.split_at(SEALED_KEY_LENGTH);
    let seed: &[u8; 32] = seed.try_into().ok()?;
    let key: &[u8; SEALED_KEY_LENGTH] = key.try_into().ok()?;
    let alg = CoseAlg::try_from(i32::from(*alg as i8)).ok()?;
    let private_key = PrivateKeyMaterial::from_bytes(alg.key_kind(), key);
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
    derive_sealed_cred_randoms(&mut credential, seed).ok()?;
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
///   credProtect level, private key and the random seed of its hmac-secret
///   CredRandom values, sealed by the store under a key that a reset replaces
///   and bound to the relying party.  It has no signature counter of its
///   own, and counts on the global one instead.
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
