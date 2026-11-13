//! Damage that operations fail closed on: probes B1-B3 of the STO-2 finding,
//! a damaged `credential-format`, and the missing directories of either
//! layout.  For each, the store's listing and the engine name the damaged
//! file, the inspection that `pqkey status` and the daemon's start-up report
//! finds it without changing anything, and what the report says fails does
//! fail.  That passkeys cannot be listed through credential management where
//! the report says so is tested through the daemon in the `pqkey` crate
//! (`cli::key::tests`).
//!
//! Then each is repaired, as `pqkey repair` does, and every passkey whose
//! record is intact works again; and what the README's "Damaged credential
//! store" says of copies, hand edits and reset holds.  A damaged signature
//! counter is named, fails what it is said to, and is repaired the same way,
//! without a count going back.

#![expect(
    clippy::disallowed_methods,
    reason = "tests damage and remove store files directly; the store's wrappers are private"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use ciborium::value::{Integer, Value};
use pqkey_ctap::CoseAlg;
use pqkey_ctap::ctap::constants::{
    CTAP_CMD_GET_ASSERTION, CTAP_CMD_GET_INFO, CTAP_CMD_MAKE_CREDENTIAL, CTAP2_ERR_NO_CREDENTIALS,
    CTAP2_ERR_PROCESSING, CTAP2_OK,
};
use pqkey_ctap::ctap::{CtapApp, InterruptFlag, presence::AutoApprove};
use pqkey_ctap::store::{
    Corruption, CredentialRecord, CredentialStore, Damage, Fault, FileStore, Membership,
    PinStateRecord, StoreError, damage_log, damage_summary, damage_unchecked,
};

use crate::common::{TempDir, ids, logs, new_record, random_bytes};

static INTERRUPT: InterruptFlag = InterruptFlag::new();

/// What a summary says fails after damage to one record, and to several.
const RECORD: &str = "the key cannot register passkeys, or use the credential in that file";
const RECORDS: &str = "the key cannot register passkeys, or use the credentials in those files";
/// What it says after damage to membership metadata, or to the directory
/// that holds it.
const MEMBERSHIP: &str = "the key cannot register, use or list passkeys";
/// What it says after a legacy store's `credentials` directory is lost.
const LEGACY_DIRECTORY: &str = "the key cannot use any passkeys that were in it";
/// What it says after damage to the shared signature counter.
const COUNTER: &str = "the key cannot sign in to sites that registered it as a security key and \
                       whose credentials it did not store";
/// The advice the engine's hint ends with.
const FIX: &str = "Stop the key with `pqkey stop`, keep a copy of the state directory, run `pqkey \
                   repair`, then start the key again with `pqkey start`; `pqkey reset` erases \
                   every passkey, so use it only as a last resort";

/// A discoverable credential: its ID is shaped like one made with "rk" true.
fn passkey() -> CredentialRecord {
    let mut record = new_record(CoseAlg::ES256);
    record.credential_id = [vec![1], random_bytes::<32>().to_vec()].concat();
    record
}

fn files_in(dir: &Path) -> BTreeSet<PathBuf> {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.is_file())
                .collect()
        })
        .unwrap_or_default()
}

/// Every file under `dir` with its contents, and every directory.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut found = BTreeMap::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path.clone());
                found.insert(path, None);
            } else {
                let contents = fs::read(&path).unwrap();
                found.insert(path, Some(contents));
            }
        }
    }
    found
}

/// The files under `state` named as credential records are, wherever they
/// are.
fn record_files(state: &Path) -> Vec<PathBuf> {
    snapshot(state)
        .into_keys()
        .filter(|path| {
            path.is_file()
                && path.file_name().is_some_and(|name| {
                    name.len() == 64
                        && name
                            .to_string_lossy()
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit())
                })
        })
        .collect()
}

/// Store `record` with `insert`, and return the record file it created in
/// `dir`.
fn store_and_locate(dir: &Path, insert: impl FnOnce()) -> PathBuf {
    let before = files_in(dir);
    insert();
    let created: Vec<_> = files_in(dir).difference(&before).cloned().collect();
    let [created] = created.as_slice() else {
        panic!("one new record in {}: {created:?}", dir.display());
    };
    created.clone()
}

fn flip_last_byte(path: &Path) {
    let mut contents = fs::read(path).unwrap();
    *contents.last_mut().unwrap() ^= 1;
    fs::write(path, contents).unwrap();
}

/// `path` relative to `state`, as the store names files.
fn relative(state: &Path, path: &Path) -> String {
    path.strip_prefix(state)
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

/// A store in `state` with three passkeys, and their records' files, oldest
/// first: in the managed layout, a legacy passkey the upgrade kept, at
/// `credential-set/<hash>`, then two registered since, in
/// `credential-set/records/`; in the legacy layout, three in `credentials/`.
fn passkeys_in(state: &Path, managed: bool) -> Vec<(CredentialRecord, PathBuf)> {
    let mut store = FileStore::open(state).unwrap();
    let legacy = state.join("credentials");
    let mut passkeys = Vec::new();
    for _ in 0..if managed { 1 } else { 3 } {
        let record = passkey();
        let file = store_and_locate(&legacy, || store.put(&record).unwrap());
        passkeys.push((record, file));
    }
    if managed {
        let records = state.join("credential-set").join("records");
        for _ in 0..2 {
            let record = passkey();
            let file = store_and_locate(&records, || {
                store.insert_or_replace_discoverable(&record).unwrap();
            });
            passkeys.push((record, file));
        }
        let kept = state
            .join("credential-set")
            .join(passkeys[0].1.file_name().unwrap());
        assert!(kept.is_file(), "the upgrade keeps the legacy record");
        passkeys[0].1 = kept;
    }
    passkeys
}

fn int(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn request(command: u8, parameters: Vec<(Value, Value)>) -> Vec<u8> {
    let mut bytes = vec![command];
    ciborium::ser::into_writer(&Value::Map(parameters), &mut bytes).unwrap();
    bytes
}

/// makeCredential for a new ES256 passkey on example.com: the status.
fn register(app: &mut CtapApp<'static>) -> u8 {
    let user = Value::Map(vec![
        (text("id"), Value::Bytes(random_bytes::<16>().to_vec())),
        (text("name"), text("new")),
    ]);
    let algorithms = Value::Array(vec![Value::Map(vec![
        (text("alg"), int(-7)),
        (text("type"), text("public-key")),
    ])]);
    app.call(&request(
        CTAP_CMD_MAKE_CREDENTIAL,
        vec![
            (int(1), Value::Bytes(vec![0x11; 32])),
            (int(2), Value::Map(vec![(text("id"), text("example.com"))])),
            (int(3), user),
            (int(4), algorithms),
            (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))])),
        ],
    ))[0]
}

/// getAssertion on example.com, listing `allowed`, or with no list for
/// `None`: the status.
fn sign_in(app: &mut CtapApp<'static>, allowed: Option<&[u8]>) -> u8 {
    let mut parameters = vec![
        (int(1), text("example.com")),
        (int(2), Value::Bytes(vec![0x22; 32])),
    ];
    if let Some(id) = allowed {
        parameters.push((
            int(3),
            Value::Array(vec![Value::Map(vec![
                (text("id"), Value::Bytes(id.to_vec())),
                (text("type"), text("public-key")),
            ])]),
        ));
    }
    app.call(&request(CTAP_CMD_GET_ASSERTION, parameters))[0]
}

/// Whether getInfo reports how many more credentials the key has room for:
/// the passkeys line of `pqkey status`.
fn counts(app: &mut CtapApp<'static>) -> bool {
    let response = app.call(&[CTAP_CMD_GET_INFO]);
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(entries) = ciborium::de::from_reader(&response[1..]).unwrap() else {
        panic!("getInfo returns a map");
    };
    entries.iter().any(|(key, _)| *key == int(0x14))
}

fn engine(state: &Path) -> CtapApp<'static> {
    CtapApp::with_file_store(
        FileStore::open(state).unwrap(),
        AutoApprove,
        &INTERRUPT,
        [0; 16],
    )
}

/// What the inspection finds, the same through the open store and from the
/// state directory alone, without changing a file or a directory.
#[track_caller]
fn inspect(store: &FileStore, state: &Path) -> Vec<Damage> {
    let before = snapshot(state);
    let found = store.inspect().unwrap();
    assert_eq!(FileStore::inspect_in(state).unwrap(), found);
    assert_eq!(snapshot(state), before, "inspecting changes nothing");
    found
}

/// The file and fault of each of `found`.
fn faults(found: &[Damage]) -> Vec<(String, Fault)> {
    found
        .iter()
        .map(|damage| (damage.file.clone(), damage.fault.clone()))
        .collect()
}

/// How a summary names damage: the file, and what is wrong with it.
fn shown((file, fault): &(String, Fault)) -> String {
    match fault {
        Fault::Missing => format!("{file} is missing"),
        Fault::Corrupt(reason) => format!("{file} is corrupt: {reason}"),
        Fault::Unreadable(reason) => format!("{file} cannot be read: {reason}"),
        _ => unreachable!("{fault:?}"),
    }
}

/// The messages containing `needle` logged since `before` of them were.
fn logged_since(before: usize, needle: &str) -> Vec<String> {
    logs::warnings_containing(needle).split_off(before)
}

/// Call `operation`, and return what it returned with the messages
/// containing `needle` that it logged.
fn logging<T>(needle: &str, operation: impl FnOnce() -> T) -> (T, Vec<String>) {
    let before = logs::warnings_containing(needle).len();
    let result = operation();
    (result, logged_since(before, needle))
}

/// The damage this test applies, each in a store of the layout it happens
/// in.
#[derive(Clone, Copy, Debug)]
enum Damaged {
    /// B1: a member's record in `credential-set/records/` fails
    /// authentication.
    Record,
    /// B1: a member's record in `credential-set/records/` is removed.
    RemovedRecord,
    /// B1: a legacy record the upgrade kept, in `credential-set/`, fails
    /// authentication.
    KeptRecord,
    /// The same record, removed.
    RemovedKeptRecord,
    /// B2: a record of a legacy store fails authentication.
    LegacyRecord,
    /// `credential-set/records/` is removed, and with it the records of the
    /// members registered since the upgrade.
    RecordsDirectory,
    /// B3: `credential-set/active` fails authentication.
    Manifest,
    /// `credential-set/active` is removed.
    RemovedManifest,
    /// `credential-set/active` cannot be read: a directory in its place
    /// fails reads with EISDIR, as root too.
    UnreadableManifest,
    /// `credential-format` fails authentication.
    Marker,
    /// `credential-format` is removed.
    RemovedMarker,
    /// `credential-set/` is removed, and every record with it.  The marker
    /// stays, so the inspection names the directories of both layouts: it
    /// cannot tell this from an upgrade that failed and lost `credentials/`.
    ManagedDirectory,
}

impl Damaged {
    const ALL: [Self; 12] = [
        Self::Record,
        Self::RemovedRecord,
        Self::KeptRecord,
        Self::RemovedKeptRecord,
        Self::LegacyRecord,
        Self::RecordsDirectory,
        Self::Manifest,
        Self::RemovedManifest,
        Self::UnreadableManifest,
        Self::Marker,
        Self::RemovedMarker,
        Self::ManagedDirectory,
    ];

    /// Whether the damage is to membership metadata, or to the directory
    /// that holds it, rather than to records.
    fn membership(self) -> bool {
        matches!(
            self,
            Self::Manifest
                | Self::RemovedManifest
                | Self::UnreadableManifest
                | Self::Marker
                | Self::RemovedMarker
                | Self::ManagedDirectory
        )
    }

    /// Damage the store in `state` holding `passkeys`.  Returns the damage
    /// the inspection must find, as each file and its fault, and the
    /// passkeys that it leaves unusable.
    fn apply(
        self,
        state: &Path,
        passkeys: &[(CredentialRecord, PathBuf)],
    ) -> (Vec<(String, Fault)>, Vec<CredentialRecord>) {
        let set = state.join("credential-set");
        let authentication = Fault::Corrupt(Corruption::Authentication);
        let records: Vec<_> = passkeys.iter().map(|(record, _)| record.clone()).collect();
        let one = |(record, path): &(CredentialRecord, PathBuf), fault: Fault| {
            match fault {
                Fault::Missing => fs::remove_file(path).unwrap(),
                _ => flip_last_byte(path),
            }
            (vec![(relative(state, path), fault)], vec![record.clone()])
        };
        let metadata = |file: &str, fault: Fault| (vec![(file.to_owned(), fault)], records.clone());
        match self {
            Self::Record => one(&passkeys[2], authentication),
            Self::RemovedRecord => one(&passkeys[2], Fault::Missing),
            Self::KeptRecord | Self::LegacyRecord => one(&passkeys[0], authentication),
            Self::RemovedKeptRecord => one(&passkeys[0], Fault::Missing),
            Self::RecordsDirectory => {
                fs::remove_dir_all(set.join("records")).unwrap();
                // In the manifest's order, which is the files' names'.
                let mut missing: Vec<_> = passkeys[1..]
                    .iter()
                    .map(|(_, path)| (relative(state, path), Fault::Missing))
                    .collect();
                missing.sort_by(|a, b| a.0.cmp(&b.0));
                (missing, records[1..].to_vec())
            }
            Self::Manifest => {
                flip_last_byte(&set.join("active"));
                metadata("credential-set/active", authentication)
            }
            Self::RemovedManifest => {
                fs::remove_file(set.join("active")).unwrap();
                metadata("credential-set/active", Fault::Missing)
            }
            Self::UnreadableManifest => {
                let active = set.join("active");
                fs::remove_file(&active).unwrap();
                fs::create_dir(&active).unwrap();
                let err = fs::read(&active).unwrap_err();
                let reason = format!("{}: {err}", active.display());
                metadata("credential-set/active", Fault::Unreadable(reason))
            }
            Self::Marker => {
                flip_last_byte(&state.join("credential-format"));
                metadata("credential-format", authentication)
            }
            Self::RemovedMarker => {
                fs::remove_file(state.join("credential-format")).unwrap();
                metadata("credential-format", Fault::Missing)
            }
            Self::ManagedDirectory => {
                fs::remove_dir_all(&set).unwrap();
                (
                    vec![
                        ("credential-set".to_owned(), Fault::Missing),
                        ("credentials".to_owned(), Fault::Missing),
                    ],
                    records,
                )
            }
        }
    }
}

/// Each kind of damage is named, as the file it is in, by the store's
/// listing, the engine and the inspection, which change nothing; and what
/// the summary says fails does: registration, and each damaged credential,
/// for damaged records; registration, every passkey and listing, for
/// damaged membership metadata.  `pqkey reset` erases every passkey all the
/// same.
#[test]
fn each_kind_of_damage_is_named_and_fails_what_its_summary_says() {
    logs::install();
    for damaged in Damaged::ALL {
        let scratch = TempDir::new();
        let state = scratch.path().join("state");
        let passkeys = passkeys_in(&state, !matches!(damaged, Damaged::LegacyRecord));
        let (expected, lost) = damaged.apply(&state, &passkeys);
        let store = FileStore::open(&state).unwrap();

        // The inspection, and the summary `pqkey status` and the start-up
        // report make of it.
        let found = inspect(&store, &state);
        assert_eq!(faults(&found), expected, "{damaged:?}");
        let consequence = match (damaged.membership(), expected.len()) {
            (true, _) => MEMBERSHIP,
            (false, 1) => RECORD,
            (false, _) => RECORDS,
        };
        let named: Vec<_> = expected.iter().map(shown).collect();
        assert_eq!(
            damage_summary(&found),
            format!(
                "the credential store is damaged ({}): {consequence}",
                named.join("; ")
            ),
            "{damaged:?}"
        );

        // Listing: it skips damaged records, warning about each, or fails,
        // naming the first damaged file, and in its detail every one.
        let detail = named.join("; ");
        if damaged.membership() {
            let Err(StoreError::CredentialSetUnavailable {
                object,
                detail: listed,
            }) = store.list()
            else {
                panic!("{damaged:?}: listing works");
            };
            assert_eq!((object, listed), (expected[0].0.clone(), detail.clone()));
            assert!(store.count().is_err(), "{damaged:?}");
        } else {
            let (listed, warnings) =
                logging("credential store: skipping credential: ", || store.list());
            let kept: Vec<_> = passkeys
                .iter()
                .rev()
                .filter(|(record, _)| !lost.contains(record))
                .map(|(record, _)| record.credential_id.clone())
                .collect();
            assert_eq!(ids(&listed.unwrap()), kept, "{damaged:?}");
            for damage in &named {
                let warning = format!("credential store: skipping credential: {damage}");
                assert!(warnings.contains(&warning), "{warning:?}: {warnings:?}");
            }
        }

        // Registration fails, and the engine names the damaged file, what
        // fails and what to do.  Replacement reads the members in the
        // manifest's order and stops at the first damaged one.
        let mut app = engine(&state);
        let hint = format!(
            "The credential store is damaged at {}: {}. {FIX}",
            expected[0].0,
            if damaged.membership() {
                MEMBERSHIP
            } else {
                RECORD
            }
        );
        let (status, logged) = logging(&hint, || register(&mut app));
        assert_eq!(status, CTAP2_ERR_PROCESSING, "{damaged:?}");
        // Missing files and membership refuse as unavailable membership.
        let error = if damaged.membership() {
            format!(
                "credential-set authority {} unavailable: {detail}",
                expected[0].0
            )
        } else if expected[0].1 == Fault::Missing {
            format!(
                "credential-set authority {} unavailable: {}",
                expected[0].0, named[0]
            )
        } else {
            named[0].clone()
        };
        assert_eq!(
            logged,
            [format!(
                "cannot commit a discoverable credential: {error}. {hint}"
            )],
            "{damaged:?}"
        );

        // Use: the damaged credentials cannot sign in; with damaged
        // membership no passkey can, with or without a list, and getInfo
        // cannot count them.
        let refused = if damaged.membership() {
            CTAP2_ERR_PROCESSING
        } else {
            CTAP2_ERR_NO_CREDENTIALS
        };
        for record in &lost {
            let (status, logged) = logging(&expected[0].0, || {
                sign_in(&mut app, Some(&record.credential_id))
            });
            assert_eq!(status, refused, "{damaged:?}");
            // A sign-in naming a member whose record is missing finds no
            // credential, as for one never stored, and logs nothing.
            if !damaged.membership() && expected[0].1 == Fault::Missing {
                assert_eq!(logged, [] as [String; 0], "{damaged:?}");
            }
        }
        if damaged.membership() {
            assert_eq!(sign_in(&mut app, None), CTAP2_ERR_PROCESSING, "{damaged:?}");
            let (counted, logged) = logging(&hint, || counts(&mut app));
            assert!(!counted, "{damaged:?}");
            assert_eq!(
                logged,
                [format!(
                    "cannot count credentials: credential-set authority {} unavailable: \
                     {detail}. {hint}",
                    expected[0].0
                )]
            );
        } else {
            assert!(counts(&mut app), "{damaged:?}");
        }
        drop(app);

        // `pqkey reset` erases every passkey: it replaces the key, and no
        // record is left.
        let key = state.join("keys").join("credential.key");
        let old_key = fs::read(&key).unwrap();
        let mut store = FileStore::open(&state).unwrap();
        let reset = store.clear();
        assert_ne!(fs::read(&key).unwrap(), old_key, "{damaged:?}");
        assert_eq!(record_files(&state), [] as [PathBuf; 0], "{damaged:?}");
        if reset.is_ok() {
            assert_eq!(store.count().unwrap(), 0, "{damaged:?}");
            assert_eq!(inspect(&store, &state), [], "{damaged:?}");
        } else {
            // Nothing can publish an empty manifest over a directory.
            assert!(matches!(damaged, Damaged::UnreadableManifest), "{reset:?}");
        }
    }
}

/// A legacy store whose `credentials` directory is lost, while the key is
/// stopped or while it runs.  The inspection names that directory, never one
/// the store did not have.  Opening the store creates the directory again,
/// empty, and logs the damage, once, as the daemon's start-up report and
/// `pqkey status` give it.  Either way the key cannot use the passkeys that
/// were in it; nothing else is claimed, since once the directory is back,
/// registration and listing work.
#[test]
fn a_lost_legacy_directory_is_reported_and_opening_logs_its_creation() {
    logs::install();
    // Lost while the key is stopped.
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let passkeys = passkeys_in(&state, false);
    fs::remove_dir_all(state.join("credentials")).unwrap();
    let before = snapshot(&state);
    let found = FileStore::inspect_in(&state).unwrap();
    assert_eq!(snapshot(&state), before, "inspecting changes nothing");
    assert_eq!(faults(&found), [("credentials".to_owned(), Fault::Missing)]);
    assert_eq!(
        damage_summary(&found),
        format!("the credential store is damaged (credentials is missing): {LEGACY_DIRECTORY}")
    );
    let start_up = damage_log(&found, &state.display().to_string());
    let (mut app, logged) = logging(&start_up, || engine(&state));
    assert_eq!(logged, std::slice::from_ref(&start_up));
    assert!(state.join("credentials").is_dir());
    assert_eq!(FileStore::inspect_in(&state).unwrap(), []);
    for (record, _) in &passkeys {
        assert_eq!(
            sign_in(&mut app, Some(&record.credential_id)),
            CTAP2_ERR_NO_CREDENTIALS
        );
    }
    assert_eq!(sign_in(&mut app, None), CTAP2_ERR_NO_CREDENTIALS);
    assert_eq!(
        register(&mut app),
        CTAP2_OK,
        "not claimed: registration works"
    );
    drop(app);
    let (_, logged) = logging(&start_up, || engine(&state));
    assert_eq!(logged, [] as [String; 0], "only a lost directory is logged");

    // Lost while the key runs, on the store it opened.
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let passkeys = passkeys_in(&state, false);
    let mut app = engine(&state);
    fs::remove_dir_all(state.join("credentials")).unwrap();
    let found = FileStore::inspect_in(&state).unwrap();
    assert_eq!(faults(&found), [("credentials".to_owned(), Fault::Missing)]);
    let hint = format!("The credential store is damaged at credentials: {LEGACY_DIRECTORY}. {FIX}");
    for (record, _) in &passkeys {
        let (status, logged) = logging(&hint, || sign_in(&mut app, Some(&record.credential_id)));
        assert_eq!(status, CTAP2_ERR_PROCESSING);
        assert_eq!(
            logged,
            [format!(
                "cannot read a credential: credential-set authority credentials unavailable: \
                 credentials is missing. {hint}"
            )]
        );
    }
}

/// A store that the inspection cannot read is reported as one that cannot
/// be checked, with the error: a record it cannot read, a credential key of
/// the wrong length, or a missing key with data encrypted under it.
/// `pqkey reset` erases every passkey all the same.
#[test]
fn a_store_the_inspection_cannot_read_cannot_be_checked() {
    let unchecked = |state: &Path| {
        let err = FileStore::inspect_in(state).unwrap_err();
        assert_eq!(
            damage_unchecked(&err),
            format!("the credential store cannot be checked: {err}")
        );
        err
    };
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let passkeys = passkeys_in(&state, true);
    // A directory in a record's place fails reads with EISDIR, as root too.
    let record = &passkeys[2].1;
    fs::remove_file(record).unwrap();
    fs::create_dir(record).unwrap();
    assert!(matches!(unchecked(&state), StoreError::Io { path, .. } if path == *record));
    let key = state.join("keys").join("credential.key");
    fs::write(&key, b"short").unwrap();
    assert!(matches!(
        unchecked(&state),
        StoreError::KeyUnavailable { .. }
    ));
    fs::remove_file(&key).unwrap();
    assert!(matches!(
        unchecked(&state),
        StoreError::KeyUnavailable { .. }
    ));
    FileStore::open(&state).unwrap().clear().unwrap();
    assert_eq!(record_files(&state), [] as [PathBuf; 0]);
}

/// Stores whose credentials are all usable have no damage, whatever their
/// layout, and neither the inspection nor opening them logs any: a new
/// store, which the inspection does not even create, an empty one, legacy
/// and managed stores, a reset one, and one whose upgrade failed and that
/// still uses its legacy directory.
#[test]
fn healthy_stores_have_no_damage() {
    logs::install();
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    assert_eq!(FileStore::inspect_in(&state).unwrap(), []);
    assert!(!state.exists(), "inspecting creates nothing");

    let mut store = FileStore::open(&state).unwrap();
    assert_eq!(inspect(&store, &state), [], "new");
    store.put(&passkey()).unwrap();
    store.put(&new_record(CoseAlg::MLDSA65)).unwrap();
    assert_eq!(inspect(&store, &state), [], "legacy");
    store.insert_or_replace_discoverable(&passkey()).unwrap();
    assert_eq!(inspect(&store, &state), [], "managed");
    drop(store);
    let mut store = FileStore::open(&state).unwrap();
    assert_eq!(inspect(&store, &state), [], "managed, reopened");
    store.clear().unwrap();
    assert_eq!(inspect(&store, &state), [], "reset");

    let scratch = TempDir::new();
    let failed = scratch.path().join("state");
    let mut store = FileStore::open(&failed).unwrap();
    store.put(&passkey()).unwrap();
    // A directory where the upgrade prepares its manifest fails the upgrade
    // after it has written the format marker and staged its first record.
    let blocker = failed.join("credentials").join("active");
    fs::create_dir_all(blocker.join("occupied")).unwrap();
    assert!(store.insert_or_replace_discoverable(&passkey()).is_err());
    fs::remove_dir_all(&blocker).unwrap();
    assert!(failed.join("credential-format").is_file());
    assert!(!failed.join("credential-set").exists());
    let store = FileStore::open(&failed).unwrap();
    assert_eq!(inspect(&store, &failed), [], "an upgrade that failed");
    assert_eq!(store.count().unwrap(), 1);

    for state in [&state, &failed] {
        let messages = logs::warnings_containing(&state.display().to_string());
        assert!(
            messages
                .iter()
                .all(|message| !message.contains("credential store is damaged")),
            "{messages:?}"
        );
    }
}

/// A copy of `from`, every file and directory, at `to`.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        let target = to.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_tree(&path, &target);
        } else {
            fs::copy(&path, &target).unwrap();
        }
    }
}

/// Plan the repair of the store in `state`, which must need one, check
/// that the plan names the inspection's damage first, and carry it out.
/// Returns the plan and the quarantine.
#[track_caller]
fn repair(state: &Path) -> (pqkey_ctap::store::RepairPlan, Option<PathBuf>) {
    let found = FileStore::inspect_in(state).unwrap();
    let plan = FileStore::plan_repair_in(state)
        .unwrap()
        .expect("damage to repair");
    assert_eq!(plan.damage[..found.len()], found[..]);
    let repaired = FileStore::repair_in(state, &plan).unwrap();
    assert_eq!(FileStore::inspect_in(state).unwrap(), [], "nothing is left");
    assert_eq!(FileStore::plan_repair_in(state).unwrap(), None);
    (plan, repaired.quarantine)
}

/// makeCredential for a security key, "rk" false, on example.com: its
/// credential ID, which carries the credential sealed under the store's
/// key.
fn register_security_key(app: &mut CtapApp<'static>) -> Vec<u8> {
    let user = Value::Map(vec![(text("id"), Value::Bytes(vec![9; 16]))]);
    let algorithms = Value::Array(vec![Value::Map(vec![
        (text("alg"), int(-7)),
        (text("type"), text("public-key")),
    ])]);
    let response = app.call(&request(
        CTAP_CMD_MAKE_CREDENTIAL,
        vec![
            (int(1), Value::Bytes(vec![0x11; 32])),
            (int(2), Value::Map(vec![(text("id"), text("example.com"))])),
            (int(3), user),
            (int(4), algorithms),
        ],
    ));
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(fields) = ciborium::de::from_reader(&response[1..]).unwrap() else {
        panic!("makeCredential returns a map");
    };
    let Some((_, Value::Bytes(data))) = fields.into_iter().find(|(key, _)| *key == int(2)) else {
        panic!("no authenticator data");
    };
    let length = usize::from(u16::from_be_bytes([data[53], data[54]]));
    data[55..55 + length].to_vec()
}

/// Each kind of damage, repaired: every passkey whose record is intact signs
/// in again, the key registers and counts passkeys again, and each file
/// repair moved is in its quarantine, byte for byte.  Records a lost
/// directory took with it do not come back.
#[test]
fn each_kind_of_damage_is_repaired_keeping_every_authentic_credential() {
    for damaged in Damaged::ALL {
        let scratch = TempDir::new();
        let state = scratch.path().join("state");
        let passkeys = passkeys_in(&state, !matches!(damaged, Damaged::LegacyRecord));
        let (_, lost) = damaged.apply(&state, &passkeys);
        // Damaged membership hides records that are intact; damage to a
        // record leaves it out; a lost directory takes its records with it.
        let intact: Vec<&CredentialRecord> = passkeys
            .iter()
            .filter(|(record, path)| {
                path.is_file() && (damaged.membership() || !lost.contains(record))
            })
            .map(|(record, _)| record)
            .collect();
        let before = snapshot(&state);
        let (plan, quarantine) = repair(&state);
        let expected = match damaged {
            Damaged::Manifest | Damaged::RemovedManifest | Damaged::UnreadableManifest => {
                Membership::Rebuilt
            }
            Damaged::ManagedDirectory => Membership::Created("credential-set".into()),
            Damaged::LegacyRecord => Membership::Listed,
            _ => Membership::Kept,
        };
        assert_eq!(plan.membership, expected, "{damaged:?}");
        assert_eq!(plan.passkeys, intact.len(), "{damaged:?}");
        // A lost directory is there again, without the records it held.
        if matches!(
            damaged,
            Damaged::RecordsDirectory | Damaged::ManagedDirectory
        ) {
            let records = state.join("credential-set").join("records");
            assert!(records.is_dir(), "{damaged:?}");
            assert_eq!(files_in(&records), BTreeSet::new(), "{damaged:?}");
        }
        for moved in &plan.moved {
            let held = quarantine.as_ref().unwrap().join(moved);
            match &before[&state.join(moved)] {
                Some(contents) => assert_eq!(&fs::read(&held).unwrap(), contents, "{moved}"),
                None => assert!(held.is_dir(), "{damaged:?}: {moved}"),
            }
        }
        let mut app = engine(&state);
        for (record, _) in &passkeys {
            let expected = if intact.contains(&record) {
                CTAP2_OK
            } else {
                CTAP2_ERR_NO_CREDENTIALS
            };
            assert_eq!(
                sign_in(&mut app, Some(&record.credential_id)),
                expected,
                "{damaged:?}"
            );
        }
        assert_eq!(register(&mut app), CTAP2_OK, "{damaged:?}");
        assert!(counts(&mut app), "{damaged:?}");
    }
}

/// A legacy store's lost `credentials` directory: repair creates it again,
/// empty, as opening the store would, and registration works; the passkeys
/// that were in it are gone.
#[test]
fn repair_creates_a_lost_legacy_directory_again() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let passkeys = passkeys_in(&state, false);
    fs::remove_dir_all(state.join("credentials")).unwrap();
    let (plan, quarantine) = repair(&state);
    assert_eq!(plan.membership, Membership::Created("credentials".into()));
    assert_eq!((plan.moved.len(), quarantine), (0, None));
    assert!(state.join("credentials").is_dir());
    let mut app = engine(&state);
    for (record, _) in &passkeys {
        assert_eq!(
            sign_in(&mut app, Some(&record.credential_id)),
            CTAP2_ERR_NO_CREDENTIALS
        );
    }
    assert_eq!(register(&mut app), CTAP2_OK);
}

/// U2F registration for `application`: the key handle, which carries the
/// credential sealed under the store's key.
fn register_u2f(app: &mut CtapApp<'static>, application: [u8; 32]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0x01, 0x00, 0x00, 64];
    apdu.extend_from_slice(&[0x33; 32]);
    apdu.extend_from_slice(&application);
    let response = app.call_u2f(&apdu);
    assert_eq!(response[response.len() - 2..], [0x90, 0x00]);
    assert_eq!(response[0], 0x05, "a registration response");
    let length = usize::from(response[66]);
    response[67..67 + length].to_vec()
}

/// U2F authentication with `handle` for `application`, with presence: the
/// status word.
fn authenticate_u2f(app: &mut CtapApp<'static>, application: [u8; 32], handle: &[u8]) -> [u8; 2] {
    let mut data = vec![0x44; 32];
    data.extend_from_slice(&application);
    data.push(u8::try_from(handle.len()).unwrap());
    data.extend_from_slice(handle);
    let mut apdu = vec![0x00, 0x02, 0x03, 0x00, u8::try_from(data.len()).unwrap()];
    apdu.extend_from_slice(&data);
    let response = app.call_u2f(&apdu);
    [response[response.len() - 2], response[response.len() - 1]]
}

/// A lost `credential-set` takes its passkeys with it, but repair keeps what
/// a reset would end: the PIN, and the sign-ins of sites that registered
/// the key as a security key, over CTAP 2 or U2F, whose credentials the
/// store's key seals into their IDs.
#[test]
fn repair_of_a_lost_namespace_keeps_the_pin_and_security_key_sign_ins() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let passkeys = passkeys_in(&state, true);
    let mut app = engine(&state);
    let sealed = register_security_key(&mut app);
    let application = [0x55; 32];
    let handle = register_u2f(&mut app, application);
    drop(app);
    let pin = PinStateRecord {
        pin_hash: Some(random_bytes()),
        min_pin_length_rp_ids: Vec::new(),
        persistent_tokens: [None, None],
        ..PinStateRecord::default()
    };
    FileStore::open(&state)
        .unwrap()
        .set_pin_state(&pin)
        .unwrap();
    fs::remove_dir_all(state.join("credential-set")).unwrap();
    repair(&state);
    let store = FileStore::open(&state).unwrap();
    assert_eq!(store.pin_state().unwrap(), Some(pin));
    let mut app = CtapApp::with_file_store(store, AutoApprove, &INTERRUPT, [0; 16]);
    assert_eq!(sign_in(&mut app, Some(&sealed)), CTAP2_OK);
    assert_eq!(
        authenticate_u2f(&mut app, application, &handle),
        [0x90, 0x00]
    );
    for (record, _) in &passkeys {
        assert_eq!(
            sign_in(&mut app, Some(&record.credential_id)),
            CTAP2_ERR_NO_CREDENTIALS
        );
    }
}

/// The count getAssertion on example.com returns for `id`.
fn assertion_count(app: &mut CtapApp<'static>, id: &[u8]) -> u32 {
    let response = app.call(&request(
        CTAP_CMD_GET_ASSERTION,
        vec![
            (int(1), text("example.com")),
            (int(2), Value::Bytes(vec![0x22; 32])),
            (
                int(3),
                Value::Array(vec![Value::Map(vec![
                    (text("id"), Value::Bytes(id.to_vec())),
                    (text("type"), text("public-key")),
                ])]),
            ),
        ],
    ));
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(fields) = ciborium::de::from_reader(&response[1..]).unwrap() else {
        panic!("getAssertion returns a map");
    };
    let Some((_, Value::Bytes(data))) = fields.into_iter().find(|(key, _)| *key == int(2)) else {
        panic!("no authenticator data");
    };
    u32::from_be_bytes(data[33..37].try_into().unwrap())
}

/// The count U2F authentication with `handle` for `application` returns.
fn u2f_count(app: &mut CtapApp<'static>, application: [u8; 32], handle: &[u8]) -> u32 {
    let mut data = vec![0x44; 32];
    data.extend_from_slice(&application);
    data.push(u8::try_from(handle.len()).unwrap());
    data.extend_from_slice(handle);
    let mut apdu = vec![0x00, 0x02, 0x03, 0x00, u8::try_from(data.len()).unwrap()];
    apdu.extend_from_slice(&data);
    let response = app.call_u2f(&apdu);
    assert_eq!(response[response.len() - 2..], [0x90, 0x00]);
    u32::from_be_bytes(response[1..5].try_into().unwrap())
}

/// A damaged signature counter: the inspection names it, and what the
/// summary says fails does, over CTAP 2 and U2F, with the engine naming the
/// file, what fails and what to do; sign-ins with credentials the key stored
/// count on their own counters and work, and so does registration.  Repair
/// writes the counter again, keeping the damaged one in its quarantine, and
/// every count the key returns afterwards is above every count it returned
/// before.
#[test]
fn a_damaged_counter_fails_security_key_sign_ins_until_repair_counts_on_above_them() {
    logs::install();
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let passkeys = passkeys_in(&state, true);
    // A security key's credential that the store keeps, as it keeps older
    // ones, and those with an RSA or Brainpool key or with payment enabled.
    let mut stored = new_record(CoseAlg::ES256);
    stored.credential_id = [vec![0], random_bytes::<32>().to_vec()].concat();
    stored.user_id = Vec::new();
    stored.user_name = None;
    stored.user_display_name = None;
    FileStore::open(&state).unwrap().put(&stored).unwrap();
    let mut app = engine(&state);
    let sealed = register_security_key(&mut app);
    let application = [0x55; 32];
    let handle = register_u2f(&mut app, application);
    let mut returned = Vec::new();
    for _ in 0..2 {
        returned.push(assertion_count(&mut app, &sealed));
        returned.push(u2f_count(&mut app, application, &handle));
    }
    assert_eq!(returned, [1, 2, 3, 4], "one count, shared");
    drop(app);
    let counter = state.join("signature-counter");
    flip_last_byte(&counter);
    let damaged = fs::read(&counter).unwrap();

    let store = FileStore::open(&state).unwrap();
    let found = inspect(&store, &state);
    assert_eq!(
        faults(&found),
        [(
            "signature-counter".to_owned(),
            Fault::Corrupt(Corruption::Authentication)
        )]
    );
    assert_eq!(
        damage_summary(&found),
        format!(
            "the credential store is damaged (signature-counter is corrupt: authentication \
             failed): {COUNTER}"
        )
    );
    let mut app = engine(&state);
    let hint = format!("The credential store is damaged at signature-counter: {COUNTER}. {FIX}");
    let error = "cannot read the global signature counter: signature-counter is corrupt: \
                 authentication failed";
    let (status, logged) = logging(&hint, || sign_in(&mut app, Some(&sealed)));
    assert_eq!(status, CTAP2_ERR_PROCESSING);
    assert_eq!(logged, [format!("{error}. {hint}")]);
    let (status, logged) = logging(&hint, || authenticate_u2f(&mut app, application, &handle));
    assert_eq!(status, [0x6f, 0x00]);
    assert_eq!(logged, [format!("{error}. {hint}")]);
    assert_eq!(
        sign_in(&mut app, Some(&stored.credential_id)),
        CTAP2_OK,
        "the key stored it"
    );
    for (record, _) in &passkeys {
        assert_eq!(sign_in(&mut app, Some(&record.credential_id)), CTAP2_OK);
    }
    assert_eq!(register(&mut app), CTAP2_OK);
    assert!(counts(&mut app));
    drop(app);
    assert_eq!(fs::read(&counter).unwrap(), damaged, "left as it was");

    let (plan, quarantine) = repair(&state);
    assert_eq!(plan.membership, Membership::Intact);
    assert!(plan.counter);
    assert_eq!(plan.moved, ["signature-counter"]);
    assert_eq!(
        fs::read(quarantine.unwrap().join("signature-counter")).unwrap(),
        damaged
    );
    let mut app = engine(&state);
    let sealed_count = assertion_count(&mut app, &sealed);
    let u2f = u2f_count(&mut app, application, &handle);
    let highest = *returned.iter().max().unwrap();
    assert!(sealed_count > highest, "{sealed_count} <= {highest}");
    assert_eq!(u2f, sealed_count + 1);
}

/// A rebuild brings back a passkey that was deleted, if its record was left
/// behind, as a copy restored over the store leaves it: here alone, since
/// its account had no other passkey, so the plan names no account, and the
/// passkey signs in again.  Deleting it again works.
#[test]
fn a_deleted_passkey_whose_record_was_left_behind_comes_back_in_a_rebuild() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let passkeys = passkeys_in(&state, true);
    let (deleted, file) = &passkeys[1];
    let contents = fs::read(file).unwrap();
    let mut store = FileStore::open(&state).unwrap();
    assert!(store.delete(&deleted.credential_id).unwrap());
    assert!(!file.exists(), "cleanup removed it");
    fs::write(file, &contents).unwrap();
    assert_eq!(store.get(&deleted.credential_id).unwrap(), None);
    flip_last_byte(&state.join("credential-set").join("active"));
    let (plan, _) = repair(&state);
    assert_eq!(plan.membership, Membership::Rebuilt);
    assert!(plan.shared.is_empty(), "{:?}", plan.shared);
    let accounts: Vec<_> = store
        .list()
        .unwrap()
        .into_iter()
        .filter(|record| record.user_id == deleted.user_id)
        .map(|record| record.credential_id.clone())
        .collect();
    assert_eq!(
        accounts,
        std::slice::from_ref(&deleted.credential_id),
        "alone"
    );
    let mut app = engine(&state);
    assert_eq!(sign_in(&mut app, Some(&deleted.credential_id)), CTAP2_OK);
    drop(app);
    assert!(store.delete(&deleted.credential_id).unwrap());
    assert_eq!(store.get(&deleted.credential_id).unwrap(), None);
}

/// Why the README says not to restore `credential-set/active` by hand: an
/// older copy hides the passkeys registered since, and the next change to
/// that list deletes their records, which it does not name.
#[test]
fn an_older_list_hides_newer_passkeys_and_the_next_change_deletes_their_records() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    passkeys_in(&state, true);
    let active = state.join("credential-set").join("active");
    let older = fs::read(&active).unwrap();
    let mut store = FileStore::open(&state).unwrap();
    let newer = passkey();
    let records = state.join("credential-set").join("records");
    let file = store_and_locate(&records, || {
        store.insert_or_replace_discoverable(&newer).unwrap();
    });
    fs::write(&active, older).unwrap();
    assert_eq!(store.get(&newer.credential_id).unwrap(), None);
    assert!(!ids(&store.list().unwrap()).contains(&newer.credential_id));
    assert!(file.is_file(), "hidden, not yet deleted");
    store.insert_or_replace_discoverable(&passkey()).unwrap();
    assert!(!file.exists(), "the next change deleted it");
}

/// A directory in the counter's place: the inspection names it, and sealed
/// sign-ins fail, but repair cannot replace it with a counter in one step,
/// so planning refuses, naming it, and changes nothing.  Moved out of the
/// state directory, with an empty file created in its place, as the refusal
/// says, it is damage repair handles: the next count is above every count
/// returned before.
#[test]
fn a_directory_in_the_counters_place_is_refused_until_an_empty_file_takes_it() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let mut app = engine(&state);
    let sealed = register_security_key(&mut app);
    let counts: Vec<_> = (0..3).map(|_| assertion_count(&mut app, &sealed)).collect();
    assert_eq!(counts, [1, 2, 3]);
    drop(app);
    let counter = state.join("signature-counter");
    fs::remove_file(&counter).unwrap();
    fs::create_dir(&counter).unwrap();

    let store = FileStore::open(&state).unwrap();
    let found = inspect(&store, &state);
    assert!(
        matches!(&faults(&found)[..], [(file, Fault::Unreadable(_))] if file == "signature-counter"),
        "{found:?}"
    );
    assert!(damage_summary(&found).ends_with(COUNTER), "{found:?}");
    let mut app = engine(&state);
    assert_eq!(sign_in(&mut app, Some(&sealed)), CTAP2_ERR_PROCESSING);
    drop(app);
    let before = snapshot(&state);
    let Err(StoreError::Io { path, source }) = FileStore::plan_repair_in(&state) else {
        panic!("a directory in the counter's place is planned");
    };
    assert_eq!(
        (path, source.kind()),
        (counter.clone(), std::io::ErrorKind::IsADirectory)
    );
    assert_eq!(snapshot(&state), before, "planning changes nothing");

    fs::rename(&counter, scratch.path().join("moved out")).unwrap();
    fs::write(&counter, b"").unwrap();
    let (plan, _) = repair(&state);
    assert_eq!(plan.membership, Membership::Intact);
    assert!(plan.counter);
    let mut app = engine(&state);
    let next = assertion_count(&mut app, &sealed);
    assert!(next > 3, "{next}");
}

/// Why the README says not to delete `signature-counter` by hand: nothing
/// tells a deleted counter from one never written, so the next sign-in
/// counts again from 0, below the counts sites have seen.
#[test]
fn a_deleted_counter_counts_again_from_zero() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let mut app = engine(&state);
    let sealed = register_security_key(&mut app);
    let counts: Vec<_> = (0..3).map(|_| assertion_count(&mut app, &sealed)).collect();
    assert_eq!(counts, [1, 2, 3]);
    drop(app);
    fs::remove_file(state.join("signature-counter")).unwrap();
    assert_eq!(FileStore::inspect_in(&state).unwrap(), []);
    let mut app = engine(&state);
    assert_eq!(assertion_count(&mut app, &sealed), 1);
}

/// Why the README says to delete the copy of the state directory once the
/// key works again: it holds the keys, so its passkeys stay readable after
/// the key is reset.
#[test]
fn a_copy_of_the_state_directory_keeps_its_passkeys_readable_after_a_reset() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let passkeys = passkeys_in(&state, true);
    let copy = scratch.path().join("copy");
    copy_tree(&state, &copy);
    FileStore::open(&state).unwrap().clear().unwrap();
    assert_eq!(FileStore::open(&state).unwrap().count().unwrap(), 0);
    let kept: BTreeSet<Vec<u8>> = ids(&FileStore::open(&copy).unwrap().list().unwrap())
        .into_iter()
        .collect();
    let stored: BTreeSet<Vec<u8>> = passkeys
        .iter()
        .map(|(record, _)| record.credential_id.clone())
        .collect();
    assert_eq!(kept, stored);
}

/// A missing key file makes the store one that cannot be checked, and its
/// error says to restore it from a copy made since the last reset; such a
/// copy brings every passkey back, and one made before it does not.
#[test]
fn a_key_file_restored_from_a_copy_made_since_the_last_reset_brings_the_store_back() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    passkeys_in(&state, true);
    let key = state.join("keys").join("credential.key");
    let copied = fs::read(&key).unwrap();
    fs::remove_file(&key).unwrap();
    let err = FileStore::inspect_in(&state).unwrap_err();
    assert_eq!(
        err.to_string(),
        "credential root key unavailable: the key is missing but data encrypted under it \
         exists; restore the key file from a copy of the state directory made since the last \
         reset"
    );
    fs::write(&key, &copied).unwrap();
    assert_eq!(FileStore::inspect_in(&state).unwrap(), []);
    assert_eq!(FileStore::open(&state).unwrap().count().unwrap(), 3);

    let mut store = FileStore::open(&state).unwrap();
    store.clear().unwrap();
    store.insert_or_replace_discoverable(&passkey()).unwrap();
    fs::write(&key, &copied).unwrap();
    assert_ne!(FileStore::inspect_in(&state).unwrap(), []);
}
