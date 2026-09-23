//! Tests that only apply to `FileStore`: persistence, the on-disk format,
//! encryption, tamper detection, key handling, and permissions.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use ciborium::value::Value;
use pqkey_ctap::CoseAlg;
use pqkey_ctap::store::{
    Corruption, CredentialRecord, CredentialStore, FileKeySource, FileStore, KeyDomain, KeySource,
    PinStateRecord, PrivateKeyMaterial, StoreError,
};

use crate::common::{
    ALL_ALGS, TempDir, assert_signature_verifies, attestation_record, hex, ids, logs, new_record,
    random_bytes, with_created_at,
};

// The envelope layout, restated from the format documentation on purpose: a
// change to the format has to show up as a failing test.
const MAGIC: &[u8] = b"FTSA";
const VERSION: u8 = 1;
const TYPE_CREDENTIAL: u8 = 1;
const TYPE_PIN_STATE: u8 = 2;
const TYPE_ATTESTATION: u8 = 3;
const NONCE_START: usize = 6;
const HEADER_LEN: usize = 30;
const TAG_LEN: usize = 16;

/// A temporary directory holding one state directory.
struct Scratch {
    dir: TempDir,
}

impl Scratch {
    fn new() -> Self {
        Self {
            dir: TempDir::new(),
        }
    }

    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    fn open(&self) -> FileStore {
        FileStore::open(self.state()).expect("open file store")
    }

    fn credentials_dir(&self) -> PathBuf {
        self.state().join("credentials")
    }

    fn key_path(&self, domain: KeyDomain) -> PathBuf {
        FileKeySource::new(self.state().join("keys")).key_path(domain)
    }

    fn pin_state_path(&self) -> PathBuf {
        self.state().join("pin-state")
    }

    fn attestation_path(&self) -> PathBuf {
        self.state().join("attestation")
    }

    /// Every file under the state directory with its contents.
    fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        all_files(&self.state())
            .into_iter()
            .map(|path| {
                let contents = fs::read(&path).unwrap();
                (path, contents)
            })
            .collect()
    }
}

fn is_record_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn credential_files(scratch: &Scratch) -> BTreeSet<PathBuf> {
    fs::read_dir(scratch.credentials_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| is_record_name(&path.file_name().unwrap().to_string_lossy()))
        .collect()
}

/// Insert a new credential and return the path of the file it created.
fn put_and_locate(scratch: &Scratch, store: &mut FileStore, record: &CredentialRecord) -> PathBuf {
    let before = credential_files(scratch);
    store.put(record).expect("put");
    let created: Vec<_> = credential_files(scratch)
        .difference(&before)
        .cloned()
        .collect();
    assert_eq!(created.len(), 1, "an insert creates exactly one file");
    created.into_iter().next().unwrap()
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>, dirs: &mut Vec<PathBuf>) {
    dirs.push(dir.to_path_buf());
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            walk(&entry.path(), files, dirs);
        } else {
            files.push(entry.path());
        }
    }
}

fn all_files(root: &Path) -> Vec<PathBuf> {
    let (mut files, mut dirs) = (Vec::new(), Vec::new());
    walk(root, &mut files, &mut dirs);
    files.sort();
    files
}

fn all_dirs(root: &Path) -> Vec<PathBuf> {
    let (mut files, mut dirs) = (Vec::new(), Vec::new());
    walk(root, &mut files, &mut dirs);
    dirs
}

fn relative_names(scratch: &Scratch) -> Vec<String> {
    let state = scratch.state();
    let mut names: Vec<String> = all_files(&state)
        .iter()
        .map(|path| {
            path.strip_prefix(&state)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn edit_file(path: &Path, edit: impl FnOnce(&mut Vec<u8>)) {
    let mut contents = fs::read(path).unwrap();
    edit(&mut contents);
    fs::write(path, contents).unwrap();
}

#[track_caller]
fn assert_corrupt<T: Debug>(result: Result<T, StoreError>, expected: Corruption) {
    match result {
        Err(StoreError::Corrupt { reason, .. }) if reason == expected => {}
        other => panic!("expected corruption ({expected:?}), got {other:?}"),
    }
}

#[track_caller]
fn assert_key_unavailable<T: Debug>(result: Result<T, StoreError>, expected: KeyDomain) {
    match result {
        Err(StoreError::KeyUnavailable { domain, .. }) if domain == expected => {}
        other => panic!("expected an unavailable {expected} key, got {other:?}"),
    }
}

fn pin_with_hash() -> PinStateRecord {
    PinStateRecord {
        pin_hash: Some(random_bytes()),
        pin_retries: 6,
        consecutive_failures: 1,
        pin_auth_blocked: false,
    }
}

// ---------------------------------------------------------------------------
// Persistence and format
// ---------------------------------------------------------------------------

#[test]
fn data_persists_across_reopen() {
    let scratch = Scratch::new();
    let pin = pin_with_hash();
    let attestation = attestation_record(&[1500, 900]);
    let listed = {
        let mut store = scratch.open();
        for alg in ALL_ALGS {
            store.put(&new_record(alg)).unwrap();
        }
        store.set_pin_state(&pin).unwrap();
        store.set_attestation(&attestation).unwrap();
        store.list().unwrap()
    };

    let mut store = scratch.open();
    assert_eq!(store.list().unwrap(), listed);
    for record in &listed {
        let stored = store.get(&record.credential_id).unwrap().unwrap();
        assert_eq!(&stored, record);
        assert_signature_verifies(&stored);
    }
    assert_eq!(store.pin_state().unwrap(), Some(pin));
    assert_eq!(store.attestation().unwrap(), Some(attestation));

    // Creation order carries on from the stored records after reopening.
    let newest = new_record(CoseAlg::ES256);
    store.put(&newest).unwrap();
    let relisted = store.list().unwrap();
    assert_eq!(relisted[0].credential_id, newest.credential_id);
    assert!(relisted[0].created_at > listed[0].created_at);

    let deleted = &listed[1].credential_id;
    assert!(store.delete(deleted).unwrap());
    drop(store);
    assert_eq!(scratch.open().get(deleted).unwrap(), None);
    assert_eq!(scratch.open().count().unwrap(), ALL_ALGS.len());
}

/// A sealed credential ID needs only the credential key: sealing creates that
/// key and nothing else, and a later process opens the ID with it.
#[test]
fn sealed_credential_ids_survive_reopen() {
    let scratch = Scratch::new();
    let sealed = scratch
        .open()
        .seal_credential_id(b"secret", b"aad")
        .unwrap();
    assert!(scratch.key_path(KeyDomain::Credential).exists());
    assert!(credential_files(&scratch).is_empty());
    assert!(!scratch.pin_state_path().exists());
    let opened = scratch.open().open_credential_id(&sealed, b"aad").unwrap();
    assert_eq!(opened.as_deref().map(Vec::as_slice), Some(&b"secret"[..]));
}

#[test]
fn layout_matches_the_documented_format() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    assert_eq!(
        relative_names(&scratch),
        ["keys/credential.key", "keys/device.key"],
        "opening creates both root keys and nothing else"
    );
    assert!(scratch.credentials_dir().is_dir());

    let record = new_record(CoseAlg::MLDSA44);
    let credential_path = put_and_locate(&scratch, &mut store, &record);
    store.set_pin_state(&PinStateRecord::default()).unwrap();
    store.set_attestation(&attestation_record(&[100])).unwrap();

    let credential_name = credential_path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(is_record_name(&credential_name));
    assert_ne!(credential_name, hex(&record.credential_id));
    assert_eq!(
        relative_names(&scratch),
        [
            "attestation".to_string(),
            format!("credentials/{credential_name}"),
            "keys/credential.key".into(),
            "keys/device.key".into(),
            "pin-state".into(),
        ],
        "no temporary files may be left behind"
    );

    for domain in KeyDomain::ALL {
        assert_eq!(fs::read(scratch.key_path(domain)).unwrap().len(), 32);
    }
    for (path, record_type) in [
        (credential_path, TYPE_CREDENTIAL),
        (scratch.pin_state_path(), TYPE_PIN_STATE),
        (scratch.attestation_path(), TYPE_ATTESTATION),
    ] {
        let envelope = fs::read(&path).unwrap();
        assert_eq!(&envelope[..4], MAGIC, "{}", path.display());
        assert_eq!(envelope[4], VERSION, "{}", path.display());
        assert_eq!(envelope[5], record_type, "{}", path.display());
        assert!(envelope.len() > HEADER_LEN + TAG_LEN);
    }
}

/// A post-quantum credential is small because only the 32-byte seed is
/// stored, never the expanded key or the public key.
#[test]
fn mldsa87_credential_files_stay_small() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let path = put_and_locate(&scratch, &mut store, &new_record(CoseAlg::MLDSA87));
    let len = fs::metadata(path).unwrap().len();
    assert!(len < 512, "an ML-DSA-87 credential file is {len} bytes");
}

// ---------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------

/// Store three credentials, apply `tamper` to the middle one's file, and check
/// that the damage is reported for it alone and never deletes anything.
fn check_tampering(expected: Corruption, tamper: impl FnOnce(&mut Vec<u8>)) {
    logs::install();
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let first = new_record(CoseAlg::ES256);
    let victim = new_record(CoseAlg::MLDSA65);
    let last = new_record(CoseAlg::MLDSA87);
    store.put(&first).unwrap();
    let victim_path = put_and_locate(&scratch, &mut store, &victim);
    store.put(&last).unwrap();
    let intact = store.list().unwrap();

    edit_file(&victim_path, tamper);
    let tampered = fs::read(&victim_path).unwrap();

    assert_corrupt(store.get(&victim.credential_id), expected);
    let listed = store.list().unwrap();
    assert_eq!(
        ids(&listed),
        [last.credential_id.clone(), first.credential_id.clone()]
    );
    assert_eq!(listed, [intact[0].clone(), intact[2].clone()]);
    let victim_name = victim_path.file_name().unwrap().to_string_lossy();
    let warnings = logs::warnings_containing(&format!("credentials/{victim_name}"));
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains(&expected.to_string())),
        "skipping the corrupt record must log a warning naming it: {warnings:?}"
    );
    assert_eq!(store.count().unwrap(), 2);
    assert!(store.get(&first.credential_id).unwrap().is_some());
    assert_eq!(
        fs::read(&victim_path).unwrap(),
        tampered,
        "a corrupt record is never deleted or rewritten implicitly"
    );

    // An explicit delete does remove it.
    assert!(store.delete(&victim.credential_id).unwrap());
    assert!(!victim_path.exists());
    assert_eq!(store.count().unwrap(), 2);
}

#[test]
fn flipped_ciphertext_byte_is_detected() {
    check_tampering(Corruption::Authentication, |envelope| {
        envelope[HEADER_LEN + 7] ^= 0x01;
    });
}

#[test]
fn flipped_tag_byte_is_detected() {
    check_tampering(Corruption::Authentication, |envelope| {
        let last = envelope.len() - 1;
        envelope[last] ^= 0x80;
    });
}

#[test]
fn flipped_nonce_byte_is_detected() {
    check_tampering(Corruption::Authentication, |envelope| {
        envelope[NONCE_START + 11] ^= 0x01;
    });
}

#[test]
fn truncated_file_is_detected() {
    check_tampering(Corruption::Authentication, |envelope| {
        envelope.pop();
    });
    check_tampering(Corruption::Authentication, |envelope| {
        envelope.truncate(HEADER_LEN + TAG_LEN);
    });
    check_tampering(Corruption::Length, |envelope| {
        envelope.truncate(HEADER_LEN + TAG_LEN - 1);
    });
    check_tampering(Corruption::Length, |envelope| envelope.truncate(5));
    check_tampering(Corruption::Length, Vec::clear);
}

#[test]
fn appended_bytes_are_detected() {
    check_tampering(Corruption::Authentication, |envelope| {
        envelope.extend_from_slice(&[0; 3]);
    });
}

#[test]
fn modified_header_is_detected() {
    check_tampering(Corruption::Header, |envelope| envelope[0] ^= 0x20);
    check_tampering(Corruption::Header, |envelope| envelope[4] = VERSION + 1);
    check_tampering(Corruption::Header, |envelope| envelope[5] = TYPE_PIN_STATE);
}

#[test]
fn swapped_credential_files_fail_authentication() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let a = new_record(CoseAlg::ES256);
    let b = new_record(CoseAlg::ES256);
    let c = new_record(CoseAlg::MLDSA44);
    let a_path = put_and_locate(&scratch, &mut store, &a);
    let b_path = put_and_locate(&scratch, &mut store, &b);
    store.put(&c).unwrap();

    // Same key, same record type, valid envelope, wrong name.
    fs::copy(&a_path, &b_path).unwrap();
    assert_corrupt(store.get(&b.credential_id), Corruption::Authentication);
    assert!(store.get(&a.credential_id).unwrap().is_some());
    assert_eq!(
        ids(&store.list().unwrap()),
        [c.credential_id.clone(), a.credential_id.clone()]
    );

    // Moving a file to an unused name does not make it readable either.
    let moved = scratch.credentials_dir().join("0".repeat(64));
    fs::rename(&a_path, &moved).unwrap();
    assert_eq!(store.get(&a.credential_id).unwrap(), None);
    assert_eq!(
        ids(&store.list().unwrap()),
        std::slice::from_ref(&c.credential_id)
    );
    assert_eq!(store.count().unwrap(), 1);
}

#[test]
fn objects_cannot_be_moved_between_kinds() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let record = new_record(CoseAlg::ES256);
    let credential_path = put_and_locate(&scratch, &mut store, &record);
    store.set_pin_state(&pin_with_hash()).unwrap();
    store.set_attestation(&attestation_record(&[64])).unwrap();
    let credential = fs::read(&credential_path).unwrap();
    let pin_state = fs::read(scratch.pin_state_path()).unwrap();
    let attestation = fs::read(scratch.attestation_path()).unwrap();

    fs::write(&credential_path, &pin_state).unwrap();
    assert_corrupt(store.get(&record.credential_id), Corruption::Header);
    fs::write(scratch.pin_state_path(), &credential).unwrap();
    assert_corrupt(store.pin_state(), Corruption::Header);
    fs::write(scratch.pin_state_path(), &attestation).unwrap();
    assert_corrupt(store.pin_state(), Corruption::Header);
    fs::write(scratch.attestation_path(), &pin_state).unwrap();
    assert_corrupt(store.attestation(), Corruption::Header);

    // Rewriting the type byte to match does not help: the type is
    // authenticated, and so is the name.
    let mut retyped = credential.clone();
    retyped[5] = TYPE_PIN_STATE;
    fs::write(scratch.pin_state_path(), &retyped).unwrap();
    assert_corrupt(store.pin_state(), Corruption::Authentication);
    let mut retyped = pin_state.clone();
    retyped[5] = TYPE_CREDENTIAL;
    fs::write(&credential_path, &retyped).unwrap();
    assert_corrupt(store.get(&record.credential_id), Corruption::Authentication);
}

#[test]
fn corrupt_pin_state_and_attestation_are_reported_and_replaceable() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let record = new_record(CoseAlg::MLDSA44);
    store.put(&record).unwrap();
    store.set_pin_state(&pin_with_hash()).unwrap();
    store.set_attestation(&attestation_record(&[64])).unwrap();

    edit_file(&scratch.pin_state_path(), |envelope| {
        envelope[HEADER_LEN] ^= 1
    });
    edit_file(&scratch.attestation_path(), |envelope| {
        envelope.truncate(envelope.len() - 1);
    });
    assert_corrupt(store.pin_state(), Corruption::Authentication);
    assert_corrupt(store.attestation(), Corruption::Authentication);
    assert!(store.get(&record.credential_id).unwrap().is_some());
    assert_eq!(store.count().unwrap(), 1);

    let pin = pin_with_hash();
    store.set_pin_state(&pin).unwrap();
    assert_eq!(store.pin_state().unwrap(), Some(pin));
    let attestation = attestation_record(&[32]);
    store.set_attestation(&attestation).unwrap();
    assert_eq!(store.attestation().unwrap(), Some(attestation));
}

#[test]
fn replacing_a_corrupt_credential_counts_as_an_insert() {
    let scratch = Scratch::new();
    let mut store = scratch.open().with_max_credentials(2);
    let victim = new_record(CoseAlg::ES256);
    let victim_path = put_and_locate(&scratch, &mut store, &victim);
    let other = new_record(CoseAlg::ES256);
    store.put(&other).unwrap();
    edit_file(&victim_path, |envelope| envelope[HEADER_LEN] ^= 1);

    // The corrupt record does not occupy a slot, and writing the same ID
    // again replaces the unreadable file with a readable newest credential.
    assert_eq!(store.count().unwrap(), 1);
    store.put(&victim).unwrap();
    assert_eq!(
        ids(&store.list().unwrap()),
        [victim.credential_id.clone(), other.credential_id.clone()]
    );
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

#[test]
fn wrong_credential_key_fails_authentication_and_deletes_nothing() {
    logs::install();
    let scratch = Scratch::new();
    let pin = pin_with_hash();
    let attestation = attestation_record(&[256]);
    let listed = {
        let mut store = scratch.open();
        for alg in ALL_ALGS {
            store.put(&new_record(alg)).unwrap();
        }
        store.set_pin_state(&pin).unwrap();
        store.set_attestation(&attestation).unwrap();
        store.list().unwrap()
    };
    let credential_files = credential_files(&scratch);
    assert_eq!(credential_files.len(), ALL_ALGS.len());
    let key_path = scratch.key_path(KeyDomain::Credential);
    let original_key = fs::read(&key_path).unwrap();
    let wrong_key = random_bytes::<32>();
    fs::write(&key_path, wrong_key).unwrap();
    let before = scratch.snapshot();

    let store = scratch.open();
    for record in &listed {
        // File names are keyed too, so under the wrong key a lookup by ID
        // finds nothing rather than someone else's file.
        assert_eq!(store.get(&record.credential_id).unwrap(), None);
    }
    assert_eq!(store.list().unwrap(), []);
    assert_eq!(store.count().unwrap(), 0);
    // Listing did try every file, and each one failed authentication.
    for path in &credential_files {
        let name = path.file_name().unwrap().to_string_lossy();
        let warnings = logs::warnings_containing(&format!("credentials/{name}"));
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("authentication failed")),
            "no authentication failure logged for {name}: {warnings:?}"
        );
    }
    assert_corrupt(store.pin_state(), Corruption::Authentication);
    assert_eq!(store.attestation().unwrap(), Some(attestation.clone()));
    assert_eq!(
        scratch.snapshot(),
        before,
        "records that fail authentication are never deleted or rewritten"
    );
    drop(store);

    // With the right key every record is readable again, so nothing was lost.
    fs::write(&key_path, &original_key).unwrap();
    let store = scratch.open();
    assert_eq!(store.list().unwrap(), listed);
    assert_eq!(store.pin_state().unwrap(), Some(pin));
}

/// Under the wrong key, a record placed at the name the wrong key assigns to
/// it still fails authentication.
#[test]
fn record_sealed_under_another_key_fails_authentication() {
    let record = new_record(CoseAlg::MLDSA65);
    let foreign = Scratch::new();
    let mut foreign_store = foreign.open();
    let foreign_path = put_and_locate(&foreign, &mut foreign_store, &record);

    let scratch = Scratch::new();
    let mut store = scratch.open();
    let own_path = put_and_locate(&scratch, &mut store, &record);
    fs::copy(&foreign_path, &own_path).unwrap();
    assert_corrupt(store.get(&record.credential_id), Corruption::Authentication);
    assert_eq!(store.list().unwrap(), []);
}

#[test]
fn wrong_device_key_affects_only_the_attestation() {
    let scratch = Scratch::new();
    let record = new_record(CoseAlg::ES256);
    {
        let mut store = scratch.open();
        store.put(&record).unwrap();
        store.set_attestation(&attestation_record(&[256])).unwrap();
    }
    fs::write(scratch.key_path(KeyDomain::Device), random_bytes::<32>()).unwrap();
    let store = scratch.open();
    assert_corrupt(store.attestation(), Corruption::Authentication);
    assert!(store.get(&record.credential_id).unwrap().is_some());
    assert!(scratch.attestation_path().exists());
}

#[test]
fn malformed_key_file_is_a_hard_error() {
    for len in [0usize, 1, 31, 33, 64] {
        // Credential key.
        let scratch = Scratch::new();
        let record = new_record(CoseAlg::MLDSA44);
        let attestation = attestation_record(&[128]);
        {
            let mut store = scratch.open();
            store.put(&record).unwrap();
            store.set_pin_state(&pin_with_hash()).unwrap();
            store.set_attestation(&attestation).unwrap();
        }
        let key_path = scratch.key_path(KeyDomain::Credential);
        let malformed = vec![0x5a; len];
        fs::write(&key_path, &malformed).unwrap();
        let before = scratch.snapshot();

        let mut store = scratch.open();
        let credential = KeyDomain::Credential;
        assert_key_unavailable(store.get(&record.credential_id), credential);
        assert_key_unavailable(store.list(), credential);
        assert_key_unavailable(store.count(), credential);
        assert_key_unavailable(store.pin_state(), credential);
        assert_key_unavailable(store.put(&new_record(CoseAlg::ES256)), credential);
        assert_key_unavailable(store.set_pin_state(&pin_with_hash()), credential);
        assert_key_unavailable(store.delete(&record.credential_id), credential);
        assert_key_unavailable(
            FileKeySource::new(scratch.state().join("keys")).load(credential),
            credential,
        );
        assert_eq!(store.attestation().unwrap(), Some(attestation.clone()));
        assert_eq!(
            scratch.snapshot(),
            before,
            "a malformed key file of {len} bytes must not be replaced"
        );
        drop(store);

        // Device key.
        let scratch = Scratch::new();
        let record = new_record(CoseAlg::ES256);
        {
            let mut store = scratch.open();
            store.put(&record).unwrap();
            store.set_attestation(&attestation).unwrap();
        }
        fs::write(scratch.key_path(KeyDomain::Device), &malformed).unwrap();
        let before = scratch.snapshot();
        let mut store = scratch.open();
        assert_key_unavailable(store.attestation(), KeyDomain::Device);
        assert_key_unavailable(store.set_attestation(&attestation), KeyDomain::Device);
        assert!(store.get(&record.credential_id).unwrap().is_some());
        assert_eq!(scratch.snapshot(), before);
    }
}

#[test]
fn missing_key_with_existing_data_is_not_regenerated() {
    let scratch = Scratch::new();
    let record = new_record(CoseAlg::MLDSA87);
    let attestation = attestation_record(&[128]);
    {
        let mut store = scratch.open();
        store.put(&record).unwrap();
        store.set_pin_state(&pin_with_hash()).unwrap();
        store.set_attestation(&attestation).unwrap();
    }
    fs::remove_file(scratch.key_path(KeyDomain::Credential)).unwrap();
    let before = scratch.snapshot();

    let mut store = scratch.open();
    let credential = KeyDomain::Credential;
    assert_key_unavailable(store.get(&record.credential_id), credential);
    assert_key_unavailable(store.list(), credential);
    assert_key_unavailable(store.pin_state(), credential);
    assert_key_unavailable(store.put(&new_record(CoseAlg::ES256)), credential);
    assert_key_unavailable(store.set_pin_state(&pin_with_hash()), credential);
    assert_eq!(store.attestation().unwrap(), Some(attestation.clone()));
    assert!(!scratch.key_path(KeyDomain::Credential).exists());
    assert_eq!(scratch.snapshot(), before);
    drop(store);

    fs::remove_file(scratch.key_path(KeyDomain::Device)).unwrap();
    let mut store = scratch.open();
    assert_key_unavailable(store.attestation(), KeyDomain::Device);
    assert_key_unavailable(store.set_attestation(&attestation), KeyDomain::Device);
    assert!(!scratch.key_path(KeyDomain::Device).exists());
}

#[test]
fn clear_recovers_from_an_unusable_credential_key() {
    for damage in ["malformed", "missing"] {
        let scratch = Scratch::new();
        {
            let mut store = scratch.open();
            store.put(&new_record(CoseAlg::ES256)).unwrap();
            store.set_pin_state(&pin_with_hash()).unwrap();
        }
        let key_path = scratch.key_path(KeyDomain::Credential);
        match damage {
            "malformed" => fs::write(&key_path, b"short").unwrap(),
            _ => fs::remove_file(&key_path).unwrap(),
        }

        let mut store = scratch.open();
        assert!(store.count().is_err(), "{damage}");
        store.clear().unwrap();
        assert_eq!(store.count().unwrap(), 0, "{damage}");
        assert_eq!(store.pin_state().unwrap(), Some(PinStateRecord::default()));
        let record = new_record(CoseAlg::MLDSA44);
        store.put(&record).unwrap();
        assert!(store.get(&record.credential_id).unwrap().is_some());
        assert_eq!(fs::read(&key_path).unwrap().len(), 32);
    }
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

#[test]
fn clear_crypto_shreds_old_ciphertext() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let record = new_record(CoseAlg::MLDSA65);
    let credential_path = put_and_locate(&scratch, &mut store, &record);
    let stored = store.get(&record.credential_id).unwrap().unwrap();
    let pin = pin_with_hash();
    store.set_pin_state(&pin).unwrap();

    let old_credential = fs::read(&credential_path).unwrap();
    let old_pin_state = fs::read(scratch.pin_state_path()).unwrap();
    let key_path = scratch.key_path(KeyDomain::Credential);
    let old_key = fs::read(&key_path).unwrap();

    store.clear().unwrap();

    let new_key = fs::read(&key_path).unwrap();
    assert_eq!(new_key.len(), 32);
    assert_ne!(new_key, old_key);
    for (path, contents) in scratch.snapshot() {
        assert!(
            !contains(&contents, &old_key),
            "the old credential key survives in {}",
            path.display()
        );
    }

    // Put the old ciphertext back exactly where it was.  Under the new key it
    // no longer authenticates, so it is invisible.
    fs::write(&credential_path, &old_credential).unwrap();
    fs::write(scratch.pin_state_path(), &old_pin_state).unwrap();
    assert_eq!(store.list().unwrap(), []);
    assert_eq!(store.count().unwrap(), 0);
    assert_eq!(store.get(&record.credential_id).unwrap(), None);
    assert_corrupt(store.pin_state(), Corruption::Authentication);
    drop(store);

    // Control: the same bytes still decrypt under the old key, so the failure
    // above is due to the key and nothing else.
    fs::write(&key_path, &old_key).unwrap();
    let store = scratch.open();
    assert_eq!(store.get(&record.credential_id).unwrap(), Some(stored));
    assert_eq!(store.pin_state().unwrap(), Some(pin));
}

#[test]
fn clear_changes_credential_file_names() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let record = new_record(CoseAlg::ES256);
    let before = put_and_locate(&scratch, &mut store, &record);
    store.clear().unwrap();
    assert!(credential_files(&scratch).is_empty());
    let after = put_and_locate(&scratch, &mut store, &record);
    assert_ne!(before, after, "file names are keyed by the rotated key");
}

#[test]
fn attestation_and_device_key_survive_clear() {
    let scratch = Scratch::new();
    let attestation = attestation_record(&[2048, 1024]);
    let (device_key, attestation_file) = {
        let mut store = scratch.open();
        store.set_attestation(&attestation).unwrap();
        store.put(&new_record(CoseAlg::MLDSA44)).unwrap();
        let device_key = fs::read(scratch.key_path(KeyDomain::Device)).unwrap();
        let attestation_file = fs::read(scratch.attestation_path()).unwrap();
        store.clear().unwrap();
        (device_key, attestation_file)
    };
    assert_eq!(
        fs::read(scratch.key_path(KeyDomain::Device)).unwrap(),
        device_key
    );
    assert_eq!(
        fs::read(scratch.attestation_path()).unwrap(),
        attestation_file
    );
    assert_eq!(scratch.open().attestation().unwrap(), Some(attestation));
}

/// Recreate on disk the state `clear` leaves behind when it is interrupted
/// after each of its steps, and check that the store is consistent in each.
#[test]
fn interrupted_clear_leaves_consistent_states() {
    // Crash during step 1: some credential files are gone; the PIN and the
    // key are untouched.
    let scratch = Scratch::new();
    let pin = pin_with_hash();
    let (a, b) = (new_record(CoseAlg::ES256), new_record(CoseAlg::MLDSA44));
    {
        let mut store = scratch.open();
        let a_path = put_and_locate(&scratch, &mut store, &a);
        store.put(&b).unwrap();
        store.set_pin_state(&pin).unwrap();
        fs::remove_file(a_path).unwrap();
    }
    let mut store = scratch.open();
    assert_eq!(
        ids(&store.list().unwrap()),
        std::slice::from_ref(&b.credential_id)
    );
    assert_eq!(store.pin_state().unwrap(), Some(pin));
    store.clear().unwrap();
    assert_eq!(store.count().unwrap(), 0);
    assert_eq!(store.pin_state().unwrap(), Some(PinStateRecord::default()));

    // Crash after step 1: no credential files; the PIN, the key and so the
    // sealed credentials are untouched, and the PIN still guards them.
    let scratch = Scratch::new();
    let pin = pin_with_hash();
    let sealed = {
        let mut store = scratch.open();
        store.put(&new_record(CoseAlg::ES256)).unwrap();
        store.set_pin_state(&pin).unwrap();
        store.seal_credential_id(b"secret", b"aad").unwrap()
    };
    for path in credential_files(&scratch) {
        fs::remove_file(path).unwrap();
    }
    let mut store = scratch.open();
    assert_eq!(store.count().unwrap(), 0);
    assert_eq!(store.pin_state().unwrap(), Some(pin.clone()));
    assert!(store.open_credential_id(&sealed, b"aad").unwrap().is_some());
    store.clear().unwrap();
    assert!(store.open_credential_id(&sealed, b"aad").unwrap().is_none());
    assert_eq!(store.pin_state().unwrap(), Some(PinStateRecord::default()));

    // Crash after step 2: new key, and the PIN state still sealed under the old
    // one.  It reads as corrupt, which the engine takes for a PIN set and
    // blocked, and no credential, stored or sealed, is left to use.
    let scratch = Scratch::new();
    let sealed = {
        let mut store = scratch.open();
        store.put(&new_record(CoseAlg::ES256)).unwrap();
        store.set_pin_state(&pin_with_hash()).unwrap();
        store.seal_credential_id(b"secret", b"aad").unwrap()
    };
    for path in credential_files(&scratch) {
        fs::remove_file(path).unwrap();
    }
    fs::write(
        scratch.key_path(KeyDomain::Credential),
        random_bytes::<32>(),
    )
    .unwrap();
    let mut store = scratch.open();
    assert_eq!(store.count().unwrap(), 0);
    assert_corrupt(store.pin_state(), Corruption::Authentication);
    assert!(store.open_credential_id(&sealed, b"aad").unwrap().is_none());
    store.clear().unwrap();
    assert_eq!(store.pin_state().unwrap(), Some(PinStateRecord::default()));
    let record = new_record(CoseAlg::MLDSA87);
    store.put(&record).unwrap();
    assert!(store.get(&record.credential_id).unwrap().is_some());
}

// ---------------------------------------------------------------------------
// Permissions and confidentiality
// ---------------------------------------------------------------------------

#[test]
fn directories_and_files_are_private() {
    let scratch = Scratch::new();
    {
        let mut store = scratch.open();
        for alg in ALL_ALGS {
            store.put(&new_record(alg)).unwrap();
        }
        store.set_pin_state(&pin_with_hash()).unwrap();
        store.set_attestation(&attestation_record(&[64])).unwrap();
        store.clear().unwrap();
        store.put(&new_record(CoseAlg::ES256)).unwrap();
    }
    scratch.open().set_pin_state(&pin_with_hash()).unwrap();

    let dirs = all_dirs(&scratch.state());
    assert_eq!(dirs.len(), 3, "state, keys, and credentials: {dirs:?}");
    for dir in dirs {
        assert_eq!(mode(&dir), 0o700, "{}", dir.display());
    }
    let files = all_files(&scratch.state());
    assert_eq!(files.len(), 5, "{files:?}");
    for file in files {
        assert_eq!(mode(&file), 0o600, "{}", file.display());
    }
}

#[test]
fn existing_directories_are_made_private() {
    let scratch = Scratch::new();
    for dir in [
        scratch.state(),
        scratch.state().join("keys"),
        scratch.credentials_dir(),
    ] {
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut store = scratch.open();
    store.put(&new_record(CoseAlg::ES256)).unwrap();
    for dir in all_dirs(&scratch.state()) {
        assert_eq!(mode(&dir), 0o700, "{}", dir.display());
    }
}

#[test]
fn open_reports_a_state_path_that_is_not_a_directory() {
    let scratch = Scratch::new();
    fs::write(scratch.state(), b"not a directory").unwrap();
    assert!(matches!(
        FileStore::open(scratch.state()),
        Err(StoreError::Io { .. })
    ));
}

/// No secret, identifier, or user-facing string may be readable from any file
/// or file name in the state directory.
#[test]
fn nothing_is_stored_in_plaintext() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let mut needles: Vec<(String, Vec<u8>)> = Vec::new();
    for (i, alg) in ALL_ALGS.into_iter().enumerate() {
        let mut record = new_record(alg);
        record.rp_id = format!("plaintext-canary-{i}.example.org");
        record.user_name = Some(format!("canary user name {i}"));
        record.user_display_name = Some(format!("Canary Display Name {i}"));
        store.put(&record).unwrap();

        let label = |what: &str| format!("{alg:?} {what}");
        needles.push((label("credential ID"), record.credential_id.clone()));
        needles.push((label("rp_id"), record.rp_id.clone().into_bytes()));
        needles.push((label("user ID"), record.user_id.clone()));
        needles.push((
            label("user name"),
            record.user_name.clone().unwrap().into_bytes(),
        ));
        needles.push((
            label("display name"),
            record.user_display_name.clone().unwrap().into_bytes(),
        ));
        needles.push((
            label("CredRandom with UV"),
            record.cred_random_with_uv.to_vec(),
        ));
        needles.push((
            label("CredRandom without UV"),
            record.cred_random_without_uv.to_vec(),
        ));
        let private_key = match &record.private_key {
            PrivateKeyMaterial::Es256 { scalar } => scalar.to_vec(),
            PrivateKeyMaterial::MlDsa { seed } => seed.to_vec(),
        };
        needles.push((label("private key"), private_key));
        // The public key is derived, not stored, so it must not appear either.
        let Value::Map(cose) =
            ciborium::de::from_reader(record.cose_public_key().unwrap().as_slice()).unwrap()
        else {
            panic!("COSE_Key must be a map");
        };
        let public_key = cose
            .iter()
            .find_map(|(label, value)| match (label, value) {
                (Value::Integer(l), Value::Bytes(bytes)) if i128::from(*l) == -1 => {
                    Some(bytes[..32].to_vec())
                }
                (Value::Integer(l), Value::Bytes(bytes)) if i128::from(*l) == -2 => {
                    Some(bytes.clone())
                }
                _ => None,
            })
            .unwrap();
        needles.push((label("public key"), public_key));
    }
    let pin = pin_with_hash();
    store.set_pin_state(&pin).unwrap();
    needles.push(("PIN hash".into(), pin.pin_hash.unwrap().to_vec()));
    let attestation = attestation_record(&[300]);
    store.set_attestation(&attestation).unwrap();
    needles.push(("attestation key".into(), attestation.private_key.to_vec()));
    needles.push((
        "attestation certificate".into(),
        attestation.certificate_chain[0].clone(),
    ));

    let state = scratch.state();
    let files = scratch.snapshot();
    assert_eq!(files.len(), ALL_ALGS.len() + 4);
    for (path, contents) in &files {
        let name = path.strip_prefix(&state).unwrap().to_string_lossy();
        for (what, needle) in &needles {
            assert!(!contains(contents, needle), "{what} is readable in {name}");
            assert!(
                !name.contains(&hex(needle)) && !contains(name.as_bytes(), needle),
                "{what} is visible in the file name {name}"
            );
        }
    }

    // Control: the scan does find bytes that really are on disk.
    let credential_key = fs::read(scratch.key_path(KeyDomain::Credential)).unwrap();
    assert!(
        files
            .values()
            .any(|contents| contains(contents, &credential_key))
    );
}

#[test]
fn every_write_uses_a_fresh_nonce() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let record = new_record(CoseAlg::MLDSA44);
    let path = put_and_locate(&scratch, &mut store, &record);
    let pin = pin_with_hash();
    let attestation = attestation_record(&[64]);
    store.set_pin_state(&pin).unwrap();
    store.set_attestation(&attestation).unwrap();
    let first: Vec<Vec<u8>> = [
        &path,
        &scratch.pin_state_path(),
        &scratch.attestation_path(),
    ]
    .iter()
    .map(|path| fs::read(path).unwrap())
    .collect();

    // Write exactly the same contents again.
    store.put(&record).unwrap();
    store.set_pin_state(&pin).unwrap();
    store.set_attestation(&attestation).unwrap();
    let second: Vec<Vec<u8>> = [
        &path,
        &scratch.pin_state_path(),
        &scratch.attestation_path(),
    ]
    .iter()
    .map(|path| fs::read(path).unwrap())
    .collect();

    for (a, b) in first.iter().zip(&second) {
        assert_eq!(a.len(), b.len());
        assert_eq!(a[..NONCE_START], b[..NONCE_START]);
        assert_ne!(a[NONCE_START..HEADER_LEN], b[NONCE_START..HEADER_LEN]);
        assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
    }
    let stored = store.get(&record.credential_id).unwrap().unwrap();
    assert_eq!(stored, with_created_at(&record, stored.created_at));
    assert_eq!(store.pin_state().unwrap(), Some(pin));
    assert_eq!(store.attestation().unwrap(), Some(attestation));
}

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------

#[test]
fn unexpected_directory_entries_are_ignored() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let records: Vec<_> = (0..2).map(|_| new_record(CoseAlg::ES256)).collect();
    for record in &records {
        store.put(record).unwrap();
    }
    let credentials = scratch.credentials_dir();
    fs::write(credentials.join("README"), b"hello").unwrap();
    fs::write(
        credentials.join(".tmp-0123456789abcdef"),
        random_bytes::<64>(),
    )
    .unwrap();
    fs::write(credentials.join("A".repeat(64)), random_bytes::<64>()).unwrap();
    fs::write(credentials.join("0".repeat(63)), random_bytes::<64>()).unwrap();
    fs::write(credentials.join("1".repeat(64)), random_bytes::<64>()).unwrap();
    fs::write(credentials.join("2".repeat(64)), vec![0u8; (1 << 20) + 1]).unwrap();
    fs::create_dir(credentials.join("f".repeat(64))).unwrap();
    fs::write(scratch.state().join(".tmp-fedcba9876543210"), b"junk").unwrap();
    fs::write(scratch.state().join("keys").join(".tmp-00"), b"junk").unwrap();

    assert_eq!(store.count().unwrap(), 2);
    let mut expected = records.clone();
    expected.reverse();
    assert_eq!(ids(&store.list().unwrap()), ids(&expected));

    store.clear().unwrap();
    let left: Vec<_> = fs::read_dir(&credentials)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["f".repeat(64)], "clear removes every file it owns");
    assert!(!scratch.state().join("keys").join(".tmp-00").exists());
    assert_eq!(store.count().unwrap(), 0);
}

#[test]
fn oversized_records_are_rejected() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let small = attestation_record(&[64]);
    store.set_attestation(&small).unwrap();
    let huge = attestation_record(&[1 << 21]);
    assert!(matches!(
        store.set_attestation(&huge),
        Err(StoreError::InvalidRecord(_))
    ));
    assert_eq!(store.attestation().unwrap(), Some(small));

    // Just under the envelope limit is fine.
    let large = attestation_record(&[(1 << 20) - 200]);
    store.set_attestation(&large).unwrap();
    assert_eq!(store.attestation().unwrap(), Some(large));
}

#[test]
fn instances_sharing_a_directory_see_each_others_changes() {
    let scratch = Scratch::new();
    let mut a = scratch.open();
    let mut b = scratch.open();

    let first = new_record(CoseAlg::MLDSA44);
    a.put(&first).unwrap();
    assert!(b.get(&first.credential_id).unwrap().is_some());

    // A reset through one instance rotates the key under the other.
    b.clear().unwrap();
    assert_eq!(a.count().unwrap(), 0);
    assert_eq!(a.pin_state().unwrap(), Some(PinStateRecord::default()));

    // Writes through the instance that did not reset use the new key.
    let second = new_record(CoseAlg::ES256);
    a.put(&second).unwrap();
    let pin = pin_with_hash();
    a.set_pin_state(&pin).unwrap();
    let reopened = scratch.open();
    assert!(reopened.get(&second.credential_id).unwrap().is_some());
    assert_eq!(reopened.pin_state().unwrap(), Some(pin));
}

#[test]
fn concurrent_first_opens_agree_on_keys() {
    let scratch = Scratch::new();
    let threads = 8;
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let state = scratch.state();
            std::thread::spawn(move || {
                barrier.wait();
                let mut store = FileStore::open(&state).expect("concurrent open");
                let record = new_record(CoseAlg::ES256);
                store.put(&record).expect("put after concurrent open");
                store.set_attestation(&attestation_record(&[16])).unwrap();
                record.credential_id.clone()
            })
        })
        .collect();
    let written: BTreeSet<Vec<u8>> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();

    let store = scratch.open();
    let listed: BTreeSet<Vec<u8>> = ids(&store.list().unwrap()).into_iter().collect();
    assert_eq!(listed, written, "every writer used the one shared key");
    assert!(store.attestation().unwrap().is_some());
    assert_eq!(
        relative_names(&scratch)
            .iter()
            .filter(|name| name.starts_with("keys/"))
            .count(),
        2
    );
}
