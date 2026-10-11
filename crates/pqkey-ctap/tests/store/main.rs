//! Tests of `pqkey_ctap::store` through its public API.
//!
//! * `conformance` runs one suite of cases, generic over `CredentialStore`,
//!   against every implementation, so the in-memory store the CTAP engine is
//!   tested with cannot drift from the file store it runs with.
//! * `file_store` covers what only the file store has: persistence, the
//!   on-disk format, encryption, tamper detection, keys, and permissions.

mod common;
mod conformance;
mod file_store;
// The library's test verifier, which it builds only for its unit tests and
// the test-support feature.  It names the algorithm as `crate::CoseAlg`.
#[path = "../../src/crypto/verify.rs"]
mod verify;

use pqkey_ctap::CoseAlg;

#[test]
fn memory_pin_writes_and_reset_are_intentionally_volatile() {
    use pqkey_ctap::store::{CommitDurability, CredentialStore, MemoryStore, PinStateRecord};
    let mut store = MemoryStore::new();
    assert_eq!(
        store.set_pin_state(&PinStateRecord::default()).unwrap(),
        CommitDurability::Volatile
    );
    assert_eq!(store.clear().unwrap(), CommitDurability::Volatile);
}
