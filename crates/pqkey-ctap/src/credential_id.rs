//! The credential ID forms shared by the engine and record validation.

use crate::store::SEALED_ID_OVERHEAD;

/// The length of the IDs of stored credentials this engine creates: a marker
/// byte and 32 random bytes.
pub(crate) const CREDENTIAL_ID_LENGTH: usize = 33;

/// The first byte of the ID of a credential created with "rk" true.
pub(crate) const DISCOVERABLE_MARKER: u8 = 0x01;

/// The first byte of the ID of a stored credential created with "rk" false,
/// including RSA and older non-discoverable credentials.
pub(crate) const NON_DISCOVERABLE_MARKER: u8 = 0x00;

/// The first byte of a sealed credential ID.
pub(crate) const SEALED_MARKER: u8 = 0x02;

/// What a sealed credential ID holds: the COSE algorithm as a signed byte, the
/// credProtect level, the 32-byte private key material (a P-256 scalar or a
/// seed), and the 32-byte random seed of its hmac-secret CredRandom values
/// (see `ctap::credential_id::derive_sealed_cred_randoms`).
pub(crate) const SEALED_PLAINTEXT_LENGTH: usize = 2 + SEALED_KEY_LENGTH + 32;

/// The length of a sealed ID's private key field, which holds the key
/// material of a sealable kind.
pub(crate) const SEALED_KEY_LENGTH: usize = 32;

/// The length of a sealed credential ID: [`SEALED_MARKER`], then the sealed
/// plaintext.
pub(crate) const SEALED_ID_LENGTH: usize = 1 + SEALED_ID_OVERHEAD + SEALED_PLAINTEXT_LENGTH;

/// Whether `credential_id` has the form of a sealed credential ID.
pub(crate) fn is_sealed(credential_id: &[u8]) -> bool {
    credential_id.len() == SEALED_ID_LENGTH && credential_id[0] == SEALED_MARKER
}

/// Whether a credential is discoverable, which its ID records.
///
/// CTAP 2.3 §6.1.2 step 18: "Otherwise, if the "rk" option is false: the
/// authenticator MUST create a non-discoverable credential", one whose
/// "credential IDs MUST be supplied by the Relying Party in
/// authenticatorGetAssertion's allowList parameter in order for the
/// authenticator to discover and employ them" (§6.1.3).  Such a credential
/// may carry its key in its ID, or name a stored record:
///
/// * A discoverable credential is a stored record with a
///   [`CREDENTIAL_ID_LENGTH`]-byte ID, [`DISCOVERABLE_MARKER`] and 32 random
///   bytes.
/// * A non-discoverable credential whose key fits is not stored. Its ID is
///   [`SEALED_ID_LENGTH`] bytes: [`SEALED_MARKER`], then its algorithm,
///   credProtect level, private key and the random seed of its hmac-secret
///   CredRandom values, sealed by the store under a key that a reset replaces
///   and bound to the relying party.  It has no signature counter of its
///   own, and counts on the global one instead.
/// * RSA credentials, whose primes do not fit a sealed ID, and older
///   non-discoverable credentials are stored records whose ID is
///   [`NON_DISCOVERABLE_MARKER`] and 32 random bytes.  They keep their own
///   signature counters and random CredRandom values, and RSA records keep no
///   user ID or names.  They take room in the store and a reset erases them,
///   but credential management neither lists nor counts them.
/// * Any other stored ID, such as the 32 random bytes of credentials created
///   before non-discoverable credentials existed, all of which were
///   discoverable, is discoverable.
///
/// The ID of a stored credential cannot be changed from outside: the store
/// authenticates each record together with its credential ID, and a
/// credential is only ever found by its exact ID.
pub(crate) fn is_discoverable(credential_id: &[u8]) -> bool {
    !is_sealed(credential_id)
        && !(credential_id.len() == CREDENTIAL_ID_LENGTH
            && credential_id[0] == NON_DISCOVERABLE_MARKER)
}
