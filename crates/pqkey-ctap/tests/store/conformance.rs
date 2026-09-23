//! One suite of behavioural cases, run against every `CredentialStore`.
//!
//! Each case is a function generic over a [`Backend`].  The
//! `conformance_suite!` invocation at the bottom instantiates every case once
//! per backend as an ordinary `#[test]`, so a failure names both the case and
//! the store it failed on (`conformance::file::delete_frees_capacity`).  A case
//! added to the list runs against every store; there is no way to add it to
//! only one.

use pqkey_ctap::CoseAlg;
use pqkey_ctap::store::{
    AttestationRecord, CredentialRecord, CredentialStore, DEFAULT_MAX_CREDENTIALS, FileStore,
    MemoryStore, PinStateRecord, PrivateKeyMaterial, SEALED_ID_OVERHEAD, StoreError,
};

use crate::common::{
    ALL_ALGS, TempDir, assert_signature_verifies, attestation_record, ids, new_record,
    random_bytes, with_created_at,
};

/// A store under test and whatever has to outlive it.
pub struct Fixture<S> {
    pub store: S,
    _dir: Option<TempDir>,
}

/// How to create a fresh, empty store.
pub trait Backend {
    type Store: CredentialStore;
    fn create(max_credentials: usize) -> Fixture<Self::Store>;
}

pub struct Memory;

impl Backend for Memory {
    type Store = MemoryStore;
    fn create(max_credentials: usize) -> Fixture<MemoryStore> {
        Fixture {
            store: MemoryStore::new().with_max_credentials(max_credentials),
            _dir: None,
        }
    }
}

pub struct File;

impl Backend for File {
    type Store = FileStore;
    fn create(max_credentials: usize) -> Fixture<FileStore> {
        let dir = TempDir::new();
        let store = FileStore::open(dir.path().join("state"))
            .expect("open file store")
            .with_max_credentials(max_credentials);
        Fixture {
            store,
            _dir: Some(dir),
        }
    }
}

fn fresh<B: Backend>() -> Fixture<B::Store> {
    B::create(DEFAULT_MAX_CREDENTIALS)
}

/// Insert `record` and return it as the store now holds it.
fn insert<S: CredentialStore>(store: &mut S, record: &CredentialRecord) -> CredentialRecord {
    store.put(record).expect("put");
    let stored = store
        .get(&record.credential_id)
        .expect("get")
        .expect("stored credential");
    assert_eq!(stored, with_created_at(record, stored.created_at));
    stored
}

// ---------------------------------------------------------------------------
// Empty store
// ---------------------------------------------------------------------------

fn empty_store_holds_nothing<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    assert_eq!(store.get(b"anything").unwrap(), None);
    assert_eq!(store.list().unwrap(), []);
    assert_eq!(store.count().unwrap(), 0);
    assert!(!store.delete(b"anything").unwrap());
    assert_eq!(store.pin_state().unwrap(), None);
    assert_eq!(store.attestation().unwrap(), None);
    assert_eq!(store.max_credentials(), DEFAULT_MAX_CREDENTIALS);
    assert_eq!(B::create(7).store.max_credentials(), 7);
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

fn round_trip<B: Backend>(alg: CoseAlg) {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let record = new_record(alg);
    let expected_public_key = record.cose_public_key().unwrap();

    let stored = insert(store, &record);
    assert_eq!(stored.alg, alg);
    assert_eq!(stored.private_key, record.private_key);
    assert_eq!(stored.cose_public_key().unwrap(), expected_public_key);
    assert_signature_verifies(&stored);
    assert_eq!(store.list().unwrap(), std::slice::from_ref(&stored));
    assert_eq!(store.count().unwrap(), 1);
}

fn es256_credential_round_trips<B: Backend>() {
    round_trip::<B>(CoseAlg::ES256);
}

fn mldsa44_credential_round_trips<B: Backend>() {
    round_trip::<B>(CoseAlg::MLDSA44);
}

fn mldsa65_credential_round_trips<B: Backend>() {
    round_trip::<B>(CoseAlg::MLDSA65);
}

fn mldsa87_credential_round_trips<B: Backend>() {
    round_trip::<B>(CoseAlg::MLDSA87);
}

fn unusual_field_values_round_trip<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let mut cases = Vec::new();

    let mut minimal = new_record(CoseAlg::ES256);
    minimal.credential_id = vec![0];
    minimal.rp_id = String::new();
    minimal.user_id = Vec::new();
    minimal.user_name = None;
    minimal.user_display_name = None;
    cases.push(minimal);

    let mut large = new_record(CoseAlg::MLDSA87);
    large.credential_id = (0..1023).map(|i| i as u8).collect();
    large.rp_id = "very.long.subdomain.".repeat(10) + "example.com";
    large.user_id = vec![0xff; 64];
    large.user_name = Some("n".repeat(64));
    large.user_display_name = Some("Ünïcødé 名前 🔐".repeat(4));
    large.sign_count = u32::MAX;
    large.cred_protect = 3;
    cases.push(large);

    let mut binary = new_record(CoseAlg::MLDSA44);
    binary.credential_id = vec![0, 0, 0, 0];
    binary.user_name = Some(String::new());
    binary.cred_protect = 2;
    binary.cred_random_with_uv = [0; 32];
    binary.cred_random_without_uv = [0xff; 32];
    cases.push(binary);

    for record in &cases {
        insert(store, record);
    }
    assert_eq!(store.count().unwrap(), cases.len());
    for record in &cases {
        let stored = store.get(&record.credential_id).unwrap().unwrap();
        assert_eq!(stored, with_created_at(record, stored.created_at));
    }
}

/// Mutating a returned record must not change what the store holds.
fn returned_records_are_copies<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let record = new_record(CoseAlg::MLDSA65);
    let mut stored = insert(store, &record);
    stored.sign_count = 99;
    stored.rp_id = "changed.example".into();
    let mut listed = store.list().unwrap();
    listed[0].user_name = None;
    let again = store.get(&record.credential_id).unwrap().unwrap();
    assert_eq!(again, with_created_at(&record, again.created_at));
}

// ---------------------------------------------------------------------------
// Insert, replace, delete
// ---------------------------------------------------------------------------

fn inserts_get_increasing_creation_order_regardless_of_input<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let mut previous = 0;
    for claimed in [u64::MAX, 0, 42, 1, u64::MAX - 1] {
        let mut record = new_record(CoseAlg::ES256);
        record.created_at = claimed;
        let stored = insert(store, &record);
        assert!(
            stored.created_at > previous,
            "creation order must increase with every insert ({} after {previous})",
            stored.created_at
        );
        previous = stored.created_at;
    }
}

fn put_replaces_existing_credential_and_keeps_its_creation_order<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let first = insert(store, &new_record(CoseAlg::MLDSA44));
    let second = insert(store, &new_record(CoseAlg::ES256));

    let mut updated = first.clone();
    updated.sign_count = 1234;
    updated.user_name = Some("renamed".into());
    updated.user_display_name = None;
    updated.cred_protect = 3;
    updated.created_at = u64::MAX;
    store.put(&updated).unwrap();

    assert_eq!(store.count().unwrap(), 2);
    let stored = store.get(&first.credential_id).unwrap().unwrap();
    assert_eq!(stored, with_created_at(&updated, first.created_at));
    assert_eq!(
        ids(&store.list().unwrap()),
        [second.credential_id.clone(), first.credential_id.clone()],
        "a replacement must not move a credential to the front"
    );
}

fn replacement_may_change_algorithm_and_key<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let original = insert(store, &new_record(CoseAlg::ES256));
    let mut replacement = new_record(CoseAlg::MLDSA87);
    replacement.credential_id = original.credential_id.clone();
    store.put(&replacement).unwrap();

    let stored = store.get(&original.credential_id).unwrap().unwrap();
    assert_eq!(stored, with_created_at(&replacement, original.created_at));
    assert_signature_verifies(&stored);
    assert_eq!(store.count().unwrap(), 1);
}

fn delete_removes_only_the_named_credential<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let a = insert(store, &new_record(CoseAlg::ES256));
    let b = insert(store, &new_record(CoseAlg::MLDSA65));
    let c = insert(store, &new_record(CoseAlg::MLDSA87));

    assert!(store.delete(&b.credential_id).unwrap());
    assert_eq!(store.get(&b.credential_id).unwrap(), None);
    assert!(
        !store.delete(&b.credential_id).unwrap(),
        "second delete finds nothing"
    );
    assert!(!store.delete(b"never stored").unwrap());

    assert_eq!(store.count().unwrap(), 2);
    assert_eq!(store.list().unwrap(), [c.clone(), a.clone()]);
    assert_eq!(store.get(&a.credential_id).unwrap(), Some(a));
    assert_eq!(store.get(&c.credential_id).unwrap(), Some(c));
}

fn similar_credential_ids_are_distinct<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let credential_ids: [&[u8]; 5] = [&[1], &[1, 0], &[1, 0, 0], &[0, 1], &[1, 1]];
    let mut records = Vec::new();
    for credential_id in credential_ids {
        let mut record = new_record(CoseAlg::ES256);
        record.credential_id = credential_id.to_vec();
        records.push(insert(store, &record));
    }
    assert_eq!(store.count().unwrap(), credential_ids.len());
    for record in &records {
        assert_eq!(
            store.get(&record.credential_id).unwrap().as_ref(),
            Some(record)
        );
    }
    assert!(store.delete(&[1, 0]).unwrap());
    assert_eq!(store.get(&[1]).unwrap().as_ref(), Some(&records[0]));
    assert_eq!(store.get(&[1, 0, 0]).unwrap().as_ref(), Some(&records[2]));
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

fn list_is_newest_first_for_rapid_inserts<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let inserted: Vec<CredentialRecord> = (0..48)
        .map(|i| new_record(ALL_ALGS[i % ALL_ALGS.len()]))
        .collect();
    for record in &inserted {
        store.put(record).unwrap();
    }
    let listed = store.list().unwrap();
    let mut expected = ids(&inserted);
    expected.reverse();
    assert_eq!(ids(&listed), expected);
    assert!(
        listed
            .windows(2)
            .all(|pair| pair[0].created_at > pair[1].created_at),
        "creation orders must be unique and strictly decreasing"
    );
    for (listed, inserted) in listed.iter().zip(inserted.iter().rev()) {
        assert_eq!(*listed, with_created_at(inserted, listed.created_at));
    }
}

fn newest_first_survives_deletes_and_replacements<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let a = insert(store, &new_record(CoseAlg::ES256));
    let b = insert(store, &new_record(CoseAlg::ES256));
    let c = insert(store, &new_record(CoseAlg::ES256));

    // Delete the newest, then insert: the new credential is still newest.
    assert!(store.delete(&c.credential_id).unwrap());
    let d = insert(store, &new_record(CoseAlg::MLDSA44));
    assert!(d.created_at > b.created_at);

    // Replace the oldest: it stays oldest.
    let mut a_updated = a.clone();
    a_updated.sign_count += 1;
    store.put(&a_updated).unwrap();

    // Re-inserting a deleted ID creates a new, newest credential.
    let mut c_again = new_record(CoseAlg::MLDSA87);
    c_again.credential_id = c.credential_id.clone();
    let c_again = insert(store, &c_again);

    assert_eq!(store.list().unwrap(), [c_again, d, b, a_updated]);
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

fn full_store_rejects_new_credentials<B: Backend>() {
    let mut fixture = B::create(3);
    let store = &mut fixture.store;
    let stored: Vec<_> = (0..3)
        .map(|_| insert(store, &new_record(CoseAlg::MLDSA44)))
        .collect();

    let rejected = new_record(CoseAlg::ES256);
    assert!(matches!(
        store.put(&rejected),
        Err(StoreError::Full { max: 3 })
    ));
    assert_eq!(store.count().unwrap(), 3);
    assert_eq!(store.get(&rejected.credential_id).unwrap(), None);
    let mut expected = stored;
    expected.reverse();
    assert_eq!(store.list().unwrap(), expected);
}

fn full_store_still_replaces_existing_credentials<B: Backend>() {
    let mut fixture = B::create(2);
    let store = &mut fixture.store;
    let first = insert(store, &new_record(CoseAlg::ES256));
    insert(store, &new_record(CoseAlg::ES256));

    let mut updated = first.clone();
    updated.sign_count = 77;
    store
        .put(&updated)
        .expect("replacing at capacity must succeed");
    assert_eq!(store.count().unwrap(), 2);
    assert_eq!(store.get(&first.credential_id).unwrap(), Some(updated));
}

fn delete_frees_capacity<B: Backend>() {
    let mut fixture = B::create(2);
    let store = &mut fixture.store;
    let first = insert(store, &new_record(CoseAlg::ES256));
    insert(store, &new_record(CoseAlg::ES256));
    let waiting = new_record(CoseAlg::MLDSA65);
    assert!(matches!(store.put(&waiting), Err(StoreError::Full { .. })));

    assert!(store.delete(&first.credential_id).unwrap());
    insert(store, &waiting);
    assert_eq!(store.count().unwrap(), 2);
    assert_eq!(
        store.list().unwrap()[0].credential_id,
        waiting.credential_id
    );
}

fn zero_capacity_rejects_every_insert<B: Backend>() {
    let mut fixture = B::create(0);
    assert!(matches!(
        fixture.store.put(&new_record(CoseAlg::ES256)),
        Err(StoreError::Full { max: 0 })
    ));
    assert_eq!(fixture.store.count().unwrap(), 0);
}

/// Hundreds of post-quantum credentials: nothing about the store may impose a
/// small size or count ceiling.
fn hundreds_of_mldsa87_credentials<B: Backend>() {
    const COUNT: usize = 300;
    let mut fixture = B::create(COUNT);
    let store = &mut fixture.store;
    let records: Vec<CredentialRecord> = (0..COUNT)
        .map(|i| {
            let mut record = new_record(CoseAlg::MLDSA87);
            record.rp_id = format!("rp-{i}.example.com");
            record.user_name = Some(format!("{i:0>64}"));
            record.user_display_name = Some("d".repeat(64));
            record.user_id = random_bytes::<64>().to_vec();
            record
        })
        .collect();
    for record in &records {
        store.put(record).unwrap();
    }
    assert!(matches!(
        store.put(&new_record(CoseAlg::MLDSA87)),
        Err(StoreError::Full { max: COUNT })
    ));

    assert_eq!(store.count().unwrap(), COUNT);
    let listed = store.list().unwrap();
    assert_eq!(listed.len(), COUNT);
    for (listed, original) in listed.iter().zip(records.iter().rev()) {
        assert_eq!(*listed, with_created_at(original, listed.created_at));
    }
    for (i, original) in records.iter().enumerate() {
        let stored = store.get(&original.credential_id).unwrap().unwrap();
        assert_eq!(stored, with_created_at(original, stored.created_at));
        // Key expansion and signing are the slow part; a spread of samples
        // proves the keys survived without making the suite crawl.
        if i % 50 == 0 || i == COUNT - 1 {
            assert_signature_verifies(&stored);
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn inconsistent_records_are_rejected_and_not_stored<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;

    let mut empty_id = new_record(CoseAlg::ES256);
    empty_id.credential_id.clear();

    let mut es256_with_seed = new_record(CoseAlg::ES256);
    es256_with_seed.private_key = PrivateKeyMaterial::generate(CoseAlg::MLDSA44);

    let mut mldsa_with_scalar = new_record(CoseAlg::MLDSA65);
    mldsa_with_scalar.private_key = PrivateKeyMaterial::generate(CoseAlg::ES256);

    let mut zero_scalar = new_record(CoseAlg::ES256);
    zero_scalar.private_key = PrivateKeyMaterial::Es256 { scalar: [0; 32] };

    let mut scalar_above_order = new_record(CoseAlg::ES256);
    scalar_above_order.private_key = PrivateKeyMaterial::Es256 { scalar: [0xff; 32] };

    let mut cred_protect_zero = new_record(CoseAlg::ES256);
    cred_protect_zero.cred_protect = 0;

    let mut cred_protect_four = new_record(CoseAlg::ES256);
    cred_protect_four.cred_protect = 4;

    for (name, record) in [
        ("empty credential ID", &empty_id),
        ("ES256 alg with ML-DSA seed", &es256_with_seed),
        ("ML-DSA alg with P-256 scalar", &mldsa_with_scalar),
        ("zero P-256 scalar", &zero_scalar),
        ("P-256 scalar above the group order", &scalar_above_order),
        ("credProtect 0", &cred_protect_zero),
        ("credProtect 4", &cred_protect_four),
    ] {
        assert!(
            matches!(store.put(record), Err(StoreError::InvalidRecord(_))),
            "{name}"
        );
    }
    assert_eq!(store.count().unwrap(), 0);

    // An invalid replacement leaves the stored credential untouched.
    let stored = insert(store, &new_record(CoseAlg::MLDSA44));
    let mut broken = stored.clone();
    broken.alg = CoseAlg::ES256;
    assert!(matches!(
        store.put(&broken),
        Err(StoreError::InvalidRecord(_))
    ));
    assert_eq!(store.get(&stored.credential_id).unwrap(), Some(stored));
}

fn invalid_attestation_is_rejected<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let valid = attestation_record(&[512]);
    store.set_attestation(&valid).unwrap();

    let mut empty_chain = valid.clone();
    empty_chain.certificate_chain.clear();
    let mut empty_certificate = valid.clone();
    empty_certificate.certificate_chain.push(Vec::new());
    let mut zero_key = valid.clone();
    zero_key.private_key = [0; 32];
    for (name, record) in [
        ("empty chain", empty_chain),
        ("empty certificate", empty_certificate),
        ("zero private key", zero_key),
    ] {
        assert!(
            matches!(
                store.set_attestation(&record),
                Err(StoreError::InvalidRecord(_))
            ),
            "{name}"
        );
    }
    assert_eq!(store.attestation().unwrap(), Some(valid));
}

// ---------------------------------------------------------------------------
// PIN state and attestation
// ---------------------------------------------------------------------------

fn pin_state_round_trips<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let set = PinStateRecord {
        pin_hash: Some(random_bytes()),
        pin_retries: 3,
        consecutive_failures: 2,
        pin_auth_blocked: true,
    };
    store.set_pin_state(&set).unwrap();
    assert_eq!(store.pin_state().unwrap(), Some(set.clone()));

    let cleared = PinStateRecord {
        pin_hash: None,
        pin_retries: 0,
        consecutive_failures: 0,
        pin_auth_blocked: false,
    };
    store.set_pin_state(&cleared).unwrap();
    assert_eq!(store.pin_state().unwrap(), Some(cleared));

    store.set_pin_state(&PinStateRecord::default()).unwrap();
    assert_eq!(store.pin_state().unwrap(), Some(PinStateRecord::default()));
}

fn pin_state_is_independent_of_credentials<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let state = PinStateRecord {
        pin_hash: Some(random_bytes()),
        ..PinStateRecord::default()
    };
    store.set_pin_state(&state).unwrap();
    let record = insert(store, &new_record(CoseAlg::ES256));
    assert!(store.delete(&record.credential_id).unwrap());
    assert_eq!(store.pin_state().unwrap(), Some(state));
    assert_eq!(store.count().unwrap(), 0);
}

fn attestation_round_trips_without_a_size_cap<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let small = attestation_record(&[700, 900]);
    store.set_attestation(&small).unwrap();
    assert_eq!(store.attestation().unwrap(), Some(small));

    // A chain far beyond the 1 KB that used to cap every stored message.
    let large: AttestationRecord = attestation_record(&[16_384, 32_768, 8_192, 1]);
    store.set_attestation(&large).unwrap();
    assert_eq!(store.attestation().unwrap(), Some(large));
    assert_eq!(store.count().unwrap(), 0);
    assert_eq!(store.pin_state().unwrap(), None);
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

fn clear_removes_credentials_and_resets_pin_state<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let records: Vec<_> = ALL_ALGS
        .iter()
        .map(|&alg| insert(store, &new_record(alg)))
        .collect();
    store
        .set_pin_state(&PinStateRecord {
            pin_hash: Some(random_bytes()),
            pin_retries: 1,
            consecutive_failures: 2,
            pin_auth_blocked: true,
        })
        .unwrap();

    store.clear().unwrap();

    assert_eq!(store.count().unwrap(), 0);
    assert_eq!(store.list().unwrap(), []);
    for record in &records {
        assert_eq!(store.get(&record.credential_id).unwrap(), None);
        assert!(!store.delete(&record.credential_id).unwrap());
    }
    assert_eq!(store.pin_state().unwrap(), Some(PinStateRecord::default()));
}

fn clear_keeps_the_attestation_record<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let attestation = attestation_record(&[1024, 2048]);
    store.set_attestation(&attestation).unwrap();
    insert(store, &new_record(CoseAlg::MLDSA65));
    store.clear().unwrap();
    assert_eq!(store.attestation().unwrap(), Some(attestation));
}

fn store_is_fully_usable_after_clear<B: Backend>() {
    let mut fixture = B::create(2);
    let store = &mut fixture.store;
    insert(store, &new_record(CoseAlg::ES256));
    insert(store, &new_record(CoseAlg::ES256));
    store.clear().unwrap();
    // Clearing again is harmless.
    store.clear().unwrap();
    assert_eq!(store.pin_state().unwrap(), Some(PinStateRecord::default()));

    let first = insert(store, &new_record(CoseAlg::MLDSA87));
    let second = insert(store, &new_record(CoseAlg::ES256));
    assert!(matches!(
        store.put(&new_record(CoseAlg::ES256)),
        Err(StoreError::Full { max: 2 })
    ));
    assert_eq!(store.list().unwrap(), [second, first.clone()]);
    assert_signature_verifies(&first);

    let state = PinStateRecord {
        pin_hash: Some(random_bytes()),
        ..PinStateRecord::default()
    };
    store.set_pin_state(&state).unwrap();
    assert_eq!(store.pin_state().unwrap(), Some(state));
}

fn clear_on_a_fresh_store<B: Backend>() {
    let mut fixture = fresh::<B>();
    fixture.store.clear().unwrap();
    assert_eq!(fixture.store.count().unwrap(), 0);
    assert_eq!(
        fixture.store.pin_state().unwrap(),
        Some(PinStateRecord::default())
    );
    assert_eq!(fixture.store.attestation().unwrap(), None);
}

macro_rules! conformance_suite {
    ($($case:ident),+ $(,)?) => {
        mod memory {
            $(
                #[test]
                fn $case() {
                    super::$case::<super::Memory>();
                }
            )+
        }

        mod file {
            $(
                #[test]
                fn $case() {
                    super::$case::<super::File>();
                }
            )+
        }
    };
}

// ---------------------------------------------------------------------------
// Sealed credential IDs
// ---------------------------------------------------------------------------

fn sealed_credential_ids_open_only_with_their_associated_data<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let plaintext = random_bytes::<34>();
    let sealed = store
        .seal_credential_id(&plaintext, b"example.com")
        .unwrap();
    assert_eq!(sealed.len(), plaintext.len() + SEALED_ID_OVERHEAD);
    let opened = store.open_credential_id(&sealed, b"example.com").unwrap();
    assert_eq!(opened.as_deref().map(Vec::as_slice), Some(&plaintext[..]));
    assert!(
        store
            .open_credential_id(&sealed, b"example.org")
            .unwrap()
            .is_none()
    );
    let mut altered = sealed.clone();
    *altered.last_mut().unwrap() ^= 0x80;
    assert!(
        store
            .open_credential_id(&altered, b"example.com")
            .unwrap()
            .is_none()
    );
    assert_ne!(
        sealed,
        store
            .seal_credential_id(&plaintext, b"example.com")
            .unwrap()
    );
    // Sealing stores nothing.
    assert_eq!(store.count().unwrap(), 0);
}

fn a_fresh_store_opens_no_credential_id<B: Backend>() {
    let fixture = fresh::<B>();
    let junk = random_bytes::<75>();
    assert!(
        fixture
            .store
            .open_credential_id(&junk, b"example.com")
            .unwrap()
            .is_none()
    );
}

fn clear_ends_sealed_credential_ids<B: Backend>() {
    let mut fixture = fresh::<B>();
    let store = &mut fixture.store;
    let sealed = store.seal_credential_id(b"secret", b"aad").unwrap();
    store.clear().unwrap();
    assert!(store.open_credential_id(&sealed, b"aad").unwrap().is_none());
    let resealed = store.seal_credential_id(b"secret", b"aad").unwrap();
    let opened = store.open_credential_id(&resealed, b"aad").unwrap();
    assert_eq!(opened.as_deref().map(Vec::as_slice), Some(&b"secret"[..]));
}

conformance_suite!(
    empty_store_holds_nothing,
    es256_credential_round_trips,
    mldsa44_credential_round_trips,
    mldsa65_credential_round_trips,
    mldsa87_credential_round_trips,
    unusual_field_values_round_trip,
    returned_records_are_copies,
    inserts_get_increasing_creation_order_regardless_of_input,
    put_replaces_existing_credential_and_keeps_its_creation_order,
    replacement_may_change_algorithm_and_key,
    delete_removes_only_the_named_credential,
    similar_credential_ids_are_distinct,
    list_is_newest_first_for_rapid_inserts,
    newest_first_survives_deletes_and_replacements,
    full_store_rejects_new_credentials,
    full_store_still_replaces_existing_credentials,
    delete_frees_capacity,
    zero_capacity_rejects_every_insert,
    hundreds_of_mldsa87_credentials,
    inconsistent_records_are_rejected_and_not_stored,
    invalid_attestation_is_rejected,
    pin_state_round_trips,
    pin_state_is_independent_of_credentials,
    attestation_round_trips_without_a_size_cap,
    clear_removes_credentials_and_resets_pin_state,
    clear_keeps_the_attestation_record,
    store_is_fully_usable_after_clear,
    sealed_credential_ids_open_only_with_their_associated_data,
    a_fresh_store_opens_no_credential_id,
    clear_ends_sealed_credential_ids,
    clear_on_a_fresh_store,
);
