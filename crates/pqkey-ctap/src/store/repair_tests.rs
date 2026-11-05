//! Repair of damaged credential sets: what it keeps, what it sets aside, and
//! errors and process exits at every checkpoint.

#![expect(
    clippy::disallowed_methods,
    reason = "tests damage, copy and remove store files directly, outside the store's wrappers"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::process::{Command, Stdio};

use super::*;
use crate::CoseAlg;
use crate::ctap::{CtapApp, InterruptFlag, constants::*, presence::AutoApprove};
use crate::store::{Fault, PrivateKeyMaterial, test_support::TempDir};

static INTERRUPT: InterruptFlag = InterruptFlag::new();
const RP: &str = "example.com";

/// A passkey of the account `user` on [`RP`]: any ID that is not shaped
/// like a non-discoverable one is discoverable.
fn passkey(id: &[u8], user: u8) -> CredentialRecord {
    CredentialRecord {
        credential_id: id.to_vec(),
        rp_id: RP.into(),
        user_id: vec![user],
        user_name: Some(format!("user {user}")),
        user_display_name: None,
        alg: CoseAlg::ES256,
        private_key: PrivateKeyMaterial::P256Scalar { scalar: [0x42; 32] },
        cred_random_with_uv: [1; 32],
        cred_random_without_uv: [2; 32],
        cred_blob: None,
        large_blob_key: None,
        third_party_payment: false,
        cred_protect: 1,
        sign_count: 0,
        created_at: 0,
    }
}

/// A stored credential a site registered as a security key: its ID is the
/// non-discoverable marker and 32 bytes, and it keeps no user handle, so
/// two of one site share an empty one.
fn security_key(fill: u8) -> CredentialRecord {
    let mut record = passkey(&[[0x00].as_slice(), &[fill; 32]].concat(), 0);
    record.user_id = Vec::new();
    record.user_name = None;
    record
}

fn flip_last_byte(path: &Path) {
    let mut contents = fs::read(path).unwrap();
    *contents.last_mut().unwrap() ^= 1;
    fs::write(path, contents).unwrap();
}

/// The record file of `id` in `store`, wherever its manifest, or a legacy
/// store's directory, has it.
fn record_file(store: &FileStore, id: &[u8]) -> PathBuf {
    let keys = store.credential_keys().unwrap().unwrap();
    let name = keys.file_name(id).unwrap();
    match store.membership(&keys).unwrap() {
        Ok(Some(manifest)) => store.record_dir(manifest[&name]).join(name),
        _ => store.credentials_dir.join(name),
    }
}

/// Run `operation` with every cleanup failing, so that the records it
/// retires stay on disk.
fn without_cleanup<T>(operation: impl FnOnce() -> T) -> T {
    fsio::with_hook(
        Box::new(|event, path| {
            if event == "cleanup" {
                Err(fsio::io_error(path, std::io::Error::other("cleanup fails")))
            } else {
                Ok(())
            }
        }),
        operation,
    )
}

/// Seal `record`, with the creation order `created_at`, under the store's
/// key into the record directory of `location`, as only the store writes
/// records: a record membership does not name.
fn plant(store: &FileStore, record: &CredentialRecord, created_at: u64, location: Location) {
    let keys = store.credential_keys().unwrap().unwrap();
    let name = keys.file_name(&record.credential_id).unwrap();
    let plaintext = codec::encode_credential(record, created_at).unwrap();
    let sealed = envelope::seal(
        &keys.record,
        RecordType::Credential,
        &credential_object(&name, location),
        &plaintext,
    )
    .unwrap();
    fs::write(store.record_dir(location).join(name), sealed).unwrap();
}

/// A managed store with a legacy passkey the upgrade kept, three passkeys
/// registered since, one of which replaced another of its account, whose
/// record cleanup left behind, and a stored security-key credential.  The
/// passkeys' counters are 7, and the shared one is 500.
fn managed(state: &Path) -> FileStore {
    let mut store = FileStore::open(state).unwrap();
    let mut kept = passkey(b"kept", 1);
    kept.sign_count = 7;
    store.put(&kept).unwrap();
    for (id, user) in [(b"second".as_slice(), 2), (b"third", 3), (b"retired", 4)] {
        let mut record = passkey(id, user);
        record.sign_count = 7;
        store.insert_or_replace_discoverable(&record).unwrap();
    }
    store.put(&security_key(0x51)).unwrap();
    let commit =
        without_cleanup(|| store.insert_or_replace_discoverable(&passkey(b"successor", 4)))
            .unwrap();
    assert!(commit.cleanup_pending);
    store.set_signature_counter(500).unwrap();
    store
}

/// The damage each scenario applies, in the layout it happens in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scenario {
    /// B1: a member's record fails authentication.
    Record,
    /// B1: a member's record is removed.
    RemovedRecord,
    /// B2: a legacy store's record fails authentication.
    Legacy,
    /// B2 in a store whose upgrade failed after it prepared its manifest
    /// and staged its record.
    FailedUpgrade,
    /// B3: the manifest fails authentication, while a deleted passkey's
    /// record and a record that does not authenticate are in the records'
    /// directory.
    Manifest,
    /// A directory in the manifest's place.
    UnreadableManifest,
    /// The marker fails authentication, and so does a member's record.
    Marker,
    /// The marker fails authentication, and nothing else.
    MarkerOnly,
    /// The marker and the manifest fail authentication.
    MarkerAndManifest,
    /// `credential-set/` is lost, and every record with it.
    Namespace,
    /// A legacy store's `credentials/` is lost.
    LegacyDirectory,
}

impl Scenario {
    pub(super) const ALL: [Self; 11] = [
        Self::Record,
        Self::RemovedRecord,
        Self::Legacy,
        Self::FailedUpgrade,
        Self::Manifest,
        Self::UnreadableManifest,
        Self::Marker,
        Self::MarkerOnly,
        Self::MarkerAndManifest,
        Self::Namespace,
        Self::LegacyDirectory,
    ];

    /// Set up the damaged store in `state`, with a PIN state, the shared
    /// counter and a large-blob array, which repair leaves alone.
    pub(super) fn apply(self, state: &Path) {
        let set = state.join(MANAGED_DIR);
        let legacy = |state: &Path| {
            let mut store = FileStore::open(state).unwrap();
            for (id, user) in [(b"first".as_slice(), 1), (b"second", 2), (b"third", 3)] {
                store.put(&passkey(id, user)).unwrap();
            }
            store.put(&security_key(0x52)).unwrap();
            store
        };
        let mut store = match self {
            Self::Legacy | Self::FailedUpgrade | Self::LegacyDirectory => legacy(state),
            _ => managed(state),
        };
        store.set_pin_state(&PinStateRecord::default()).unwrap();
        store.set_signature_counter(500).unwrap();
        store
            .set_large_blob_array(&INITIAL_LARGE_BLOB_ARRAY)
            .unwrap();
        match self {
            Self::Record | Self::Marker => flip_last_byte(&record_file(&store, b"third")),
            Self::RemovedRecord => fs::remove_file(record_file(&store, b"third")).unwrap(),
            Self::Legacy => flip_last_byte(&record_file(&store, b"second")),
            Self::FailedUpgrade => {
                let failed = fsio::with_hook(
                    Box::new(|event, path| {
                        if event == "publication" {
                            Err(fsio::io_error(path, std::io::Error::other("interrupted")))
                        } else {
                            Ok(())
                        }
                    }),
                    || store.insert_or_replace_discoverable(&passkey(b"staged", 5)),
                );
                assert!(failed.is_err());
                assert!(state.join(CREDENTIALS_DIR).join(ACTIVE_FILE).is_file());
                flip_last_byte(&record_file(&store, b"second"));
            }
            Self::Manifest | Self::MarkerAndManifest => {
                without_cleanup(|| store.delete(b"second")).unwrap();
                fs::write(set.join(RECORDS_DIR).join("ab".repeat(32)), b"not a record").unwrap();
                flip_last_byte(&set.join(ACTIVE_FILE));
                if self == Self::MarkerAndManifest {
                    flip_last_byte(&state.join(FORMAT_FILE));
                }
            }
            Self::UnreadableManifest => {
                fs::remove_file(set.join(ACTIVE_FILE)).unwrap();
                fs::create_dir_all(set.join(ACTIVE_FILE)).unwrap();
                fs::write(set.join(ACTIVE_FILE).join("left"), b"inside").unwrap();
            }
            Self::MarkerOnly => {}
            Self::Namespace => fs::remove_dir_all(&set).unwrap(),
            Self::LegacyDirectory => fs::remove_dir_all(state.join(CREDENTIALS_DIR)).unwrap(),
        }
        if matches!(self, Self::Marker | Self::MarkerOnly) {
            flip_last_byte(&state.join(FORMAT_FILE));
        }
    }
}

/// What a store serves: no credential at all, or the credentials it lists,
/// with their counters, and for a managed store its members.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Served {
    Unavailable,
    Legacy(Vec<(Vec<u8>, u32)>),
    Managed(Vec<(Vec<u8>, u32)>, BTreeSet<String>),
}

fn served(state: &Path) -> Served {
    let store = FileStore::unopened(state);
    let keys = store.credential_keys().unwrap().unwrap();
    let listed = || {
        let mut listed: Vec<_> = store
            .list()
            .unwrap()
            .iter()
            .map(|record| (record.credential_id.clone(), record.sign_count))
            .collect();
        listed.sort();
        listed
    };
    match store.membership(&keys).unwrap() {
        Err(_) => Served::Unavailable,
        Ok(None) => Served::Legacy(listed()),
        Ok(Some(manifest)) => Served::Managed(listed(), manifest.into_keys().collect()),
    }
}

/// Every entry under `dir`, by its path relative to `dir`: a regular file
/// with its contents, a directory or anything else without.
fn entries(dir: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut found = BTreeMap::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(current) = dirs.pop() {
        for entry in fs::read_dir(&current).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let relative = path.strip_prefix(dir).unwrap().to_path_buf();
            if metadata.is_dir() {
                dirs.push(path);
                found.insert(relative, None);
            } else if metadata.is_file() {
                found.insert(relative, Some(fs::read(&path).unwrap()));
            } else {
                found.insert(relative, None);
            }
        }
    }
    found
}

/// Every regular file under `dir`, by its path relative to `dir`.
fn files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(current) = dirs.pop() {
        for entry in fs::read_dir(&current).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                dirs.push(path);
            } else if metadata.is_file() {
                found.insert(
                    path.strip_prefix(dir).unwrap().to_path_buf(),
                    fs::read(&path).unwrap(),
                );
            }
        }
    }
    found
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        let target = to.join(path.file_name().unwrap());
        if fs::symlink_metadata(&path).unwrap().is_dir() {
            copy_tree(&path, &target);
        } else {
            fs::copy(&path, &target).unwrap();
        }
    }
}

/// Every file of `before` is still in `state` with its contents: where it
/// was, in a quarantine at its relative path, or in `credential-set/` if
/// it was in a legacy `credentials/`, which a store's first commit renames.
#[track_caller]
fn assert_nothing_lost(before: &BTreeMap<PathBuf, Vec<u8>>, state: &Path, context: &str) {
    let after = files(state);
    for (path, contents) in before {
        let renamed = path
            .strip_prefix(CREDENTIALS_DIR)
            .ok()
            .map(|rest| Path::new(MANAGED_DIR).join(rest));
        let kept = after.iter().any(|(other, held)| {
            held == contents
                && (other == path
                    || renamed.as_deref() == Some(other.as_path())
                    || other.starts_with(QUARANTINE) && other.ends_with(path))
        });
        assert!(kept, "{context}: {} was lost", path.display());
    }
}

/// The files repair never touches.
#[track_caller]
fn assert_untouched(before: &BTreeMap<PathBuf, Vec<u8>>, state: &Path, context: &str) {
    let after = files(state);
    for path in [
        PIN_STATE_FILE,
        SIGNATURE_COUNTER_FILE,
        LARGE_BLOBS_FILE,
        ATTESTATION_FILE,
    ]
    .map(PathBuf::from)
    .into_iter()
    .chain(
        before
            .keys()
            .filter(|path| path.starts_with(KEYS_DIR))
            .cloned(),
    ) {
        assert_eq!(
            before.get(&path),
            after.get(&path),
            "{context}: {}",
            path.display()
        );
    }
}

const QUARANTINE: &str = "damaged";

/// A store set up for `scenario` in a directory of its own, to be copied
/// for each run, so that every run has the same keys and file names.
struct Template {
    _scratch: TempDir,
    state: PathBuf,
    before: BTreeMap<PathBuf, Vec<u8>>,
    old: Served,
    repaired: Served,
}

impl Template {
    fn new(scenario: Scenario) -> Self {
        let scratch = TempDir::new();
        let state = scratch.path().join("template");
        scenario.apply(&state);
        let before = files(&state);
        let old = served(&state);
        let copy = scratch.path().join("repaired");
        copy_tree(&state, &copy);
        FileStore::repair_in(&copy, &plan(&copy)).unwrap();
        let repaired = served(&copy);
        assert_ne!(old, repaired, "{scenario:?}: repair changes what is served");
        Self {
            _scratch: scratch,
            state,
            before,
            old,
            repaired,
        }
    }

    /// A fresh copy of the damaged store, and the plan to repair it.  Each
    /// copy is planned for itself: an unreadable file's error names it.
    fn copy(&self, scratch: &TempDir) -> (PathBuf, RepairPlan) {
        let state = scratch.path().join("state");
        copy_tree(&self.state, &state);
        let plan = plan(&state);
        (state, plan)
    }

    /// After a repair that failed or crashed: the store serves what it
    /// served or what repair makes it serve, every file is where it was or
    /// in a quarantine, and repairing again finishes the work.  Returns
    /// whether the store served what repair makes it serve already.
    #[track_caller]
    fn assert_recovers(&self, state: &Path, context: &str) -> bool {
        let now = served(state);
        assert!(
            now == self.old || now == self.repaired,
            "{context}: serves {now:?}"
        );
        assert_nothing_lost(&self.before, state, context);
        assert_untouched(&self.before, state, context);
        if let Some(plan) = FileStore::plan_repair_in(state).unwrap() {
            FileStore::repair_in(state, &plan)
                .unwrap_or_else(|err| panic!("{context}: repairing again: {err}"));
        }
        assert_eq!(served(state), self.repaired, "{context}");
        assert_eq!(FileStore::inspect_in(state).unwrap(), [], "{context}");
        assert_nothing_lost(&self.before, state, context);
        now == self.repaired
    }
}

/// Each sweep reaches both sides of the commit: checkpoints before it,
/// which leave the store as it was, and after it.  A lost legacy directory
/// is created again by one `mkdir`, before which there is no checkpoint.
#[track_caller]
fn assert_both_sides(scenario: Scenario, outcomes: &[bool]) {
    assert!(
        outcomes.contains(&false) || scenario == Scenario::LegacyDirectory,
        "{scenario:?}: never before the commit"
    );
    assert!(
        outcomes.contains(&true),
        "{scenario:?}: never after the commit"
    );
}

/// The plan to repair the damaged store in `state`.
fn plan(state: &Path) -> RepairPlan {
    FileStore::plan_repair_in(state)
        .unwrap()
        .unwrap_or_else(|| panic!("{}: nothing to repair", state.display()))
}

/// The checkpoints of a repair of `template`, which plans it again first.
fn trace(template: &Template) -> Vec<String> {
    let scratch = TempDir::new();
    let (state, plan) = template.copy(&scratch);
    let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let recorded = events.clone();
    fsio::with_hook(
        Box::new(move |event, _| {
            recorded.borrow_mut().push(event.to_owned());
            Ok(())
        }),
        || FileStore::repair_in(&state, &plan),
    )
    .unwrap();
    events.take()
}

#[test]
fn an_error_at_every_checkpoint_leaves_the_old_or_the_repaired_store() {
    for scenario in Scenario::ALL {
        let template = Template::new(scenario);
        let events = trace(&template);
        let mut outcomes = Vec::new();
        for (boundary, event) in events.iter().enumerate() {
            let scratch = TempDir::new();
            let (state, plan) = template.copy(&scratch);
            let mut index = 0;
            let result = fsio::with_hook(
                Box::new(move |_, path| {
                    let current = index;
                    index += 1;
                    if current == boundary {
                        Err(fsio::io_error(path, std::io::Error::other("injected")))
                    } else {
                        Ok(())
                    }
                }),
                || FileStore::repair_in(&state, &plan),
            );
            let context = format!("{scenario:?}, error at {boundary}: {event}: {result:?}");
            outcomes.push(template.assert_recovers(&state, &context));
        }
        assert_both_sides(scenario, &outcomes);
    }
}

#[test]
fn repair_crash_child() {
    let Some(path) = std::env::var_os("PQKEY_REPAIR_CHILD") else {
        return;
    };
    let boundary: usize = std::env::var("PQKEY_REPAIR_BOUNDARY")
        .unwrap()
        .parse()
        .unwrap();
    let state = PathBuf::from(path);
    let plan = FileStore::plan_repair_in(&state).unwrap().unwrap();
    let mut index = 0;
    let result = fsio::with_hook(
        Box::new(move |_, _| {
            if index == boundary {
                std::process::exit(83);
            }
            index += 1;
            Ok(())
        }),
        || FileStore::repair_in(&state, &plan),
    );
    panic!("crash boundary not reached: {boundary}, {result:?}");
}

#[test]
fn a_process_exit_at_every_checkpoint_leaves_the_old_or_the_repaired_store() {
    for scenario in Scenario::ALL {
        let template = Template::new(scenario);
        let mut outcomes = Vec::new();
        for (boundary, event) in trace(&template).iter().enumerate() {
            let scratch = TempDir::new();
            let (state, _) = template.copy(&scratch);
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::file::repair_tests::repair_crash_child",
                    "--nocapture",
                ])
                .env("PQKEY_REPAIR_CHILD", &state)
                .env("PQKEY_REPAIR_BOUNDARY", boundary.to_string())
                .stdout(Stdio::null())
                .status()
                .unwrap();
            let context = format!("{scenario:?}, exit at {boundary}: {event}");
            assert_eq!(status.code(), Some(83), "{context}");
            outcomes.push(template.assert_recovers(&state, &context));
        }
        assert_both_sides(scenario, &outcomes);
    }
}

/// What a repair plans: the damage, how it repairs membership, the
/// credentials it keeps, the accounts it keeps more than one passkey of (by
/// user name, with their number), and the files it moves.
type Expected = (
    Vec<Damage>,
    Membership,
    Vec<Vec<u8>>,
    Vec<(&'static str, usize)>,
    Vec<String>,
);

/// What each repair plans, and that it does it: the members or records it
/// leaves out are each named, every file it moves is in the quarantine with
/// its contents, the store serves every authentic credential, takes new
/// registrations, and has nothing left to repair.
#[test]
fn each_repair_names_what_it_leaves_out_and_keeps_the_rest() {
    let authentication = Fault::Corrupt(Corruption::Authentication);
    for scenario in Scenario::ALL {
        let template = Template::new(scenario);
        let scratch = TempDir::new();
        let state = scratch.path().join("state");
        copy_tree(&template.state, &state);
        // Planning changes nothing, and plans the same again.
        let unplanned = entries(&state);
        let plan = plan(&state);
        assert_eq!(
            FileStore::plan_repair_in(&state).unwrap().as_ref(),
            Some(&plan),
            "{scenario:?}"
        );
        assert_eq!(
            entries(&state),
            unplanned,
            "{scenario:?}: planning changed it"
        );
        let store = FileStore::unopened(&state);
        let keys = store.credential_keys().unwrap().unwrap();
        let name_of = |id: &[u8]| keys.file_name(id).unwrap();
        let file_of = |id: &[u8], dir: &str| format!("{dir}/{}", name_of(id));
        let records = format!("{MANAGED_DIR}/{RECORDS_DIR}");
        let active = format!("{MANAGED_DIR}/{ACTIVE_FILE}");
        let corrupt = |file: String| Damage {
            file,
            fault: authentication.clone(),
        };
        let managed_security = security_key(0x51).credential_id.clone();
        let legacy_security = security_key(0x52).credential_id.clone();
        let managed_kept: [&[u8]; 5] = [
            b"kept",
            b"second",
            b"third",
            b"successor",
            &managed_security,
        ];
        let without = |ids: &[&[u8]], left_out: &[u8]| -> Vec<Vec<u8>> {
            ids.iter()
                .filter(|id| **id != left_out)
                .map(|id| id.to_vec())
                .collect()
        };
        let (damage, membership, kept, shared, mut moved): Expected = match scenario {
            Scenario::Record | Scenario::RemovedRecord => (
                vec![Damage {
                    file: file_of(b"third", &records),
                    fault: if scenario == Scenario::Record {
                        authentication.clone()
                    } else {
                        Fault::Missing
                    },
                }],
                Membership::Kept,
                without(&managed_kept, b"third"),
                vec![],
                [
                    Some(active.clone()),
                    (scenario == Scenario::Record).then(|| file_of(b"third", &records)),
                    Some(file_of(b"retired", &records)),
                ]
                .into_iter()
                .flatten()
                .collect(),
            ),
            Scenario::Legacy | Scenario::FailedUpgrade => {
                let mut moved = vec![file_of(b"second", CREDENTIALS_DIR)];
                if scenario == Scenario::FailedUpgrade {
                    moved.push(format!("{CREDENTIALS_DIR}/{ACTIVE_FILE}"));
                    moved.push(file_of(
                        b"staged",
                        &format!("{CREDENTIALS_DIR}/{RECORDS_DIR}"),
                    ));
                }
                (
                    vec![corrupt(file_of(b"second", CREDENTIALS_DIR))],
                    Membership::Listed,
                    vec![
                        b"first".to_vec(),
                        b"third".to_vec(),
                        legacy_security.clone(),
                    ],
                    vec![],
                    moved,
                )
            }
            Scenario::Manifest | Scenario::MarkerAndManifest | Scenario::UnreadableManifest => {
                let mut damage = Vec::new();
                let mut moved = vec![active.clone()];
                if scenario == Scenario::MarkerAndManifest {
                    damage.push(corrupt(FORMAT_FILE.into()));
                    moved.push(FORMAT_FILE.to_owned());
                }
                damage.push(if scenario == Scenario::UnreadableManifest {
                    let path = state.join(&active);
                    let err = fs::read(&path).unwrap_err();
                    Damage {
                        file: active.clone(),
                        fault: Fault::Unreadable(format!("{}: {err}", path.display())),
                    }
                } else {
                    corrupt(active.clone())
                });
                if scenario != Scenario::UnreadableManifest {
                    // A deleted passkey whose record cleanup left behind
                    // comes back, and only a record that is not one is left
                    // out.
                    let garbage = format!("{records}/{}", "ab".repeat(32));
                    damage.push(Damage {
                        file: garbage.clone(),
                        fault: Fault::Corrupt(Corruption::Length),
                    });
                    moved.push(garbage);
                }
                // The passkey a registration of account 4 replaced comes back
                // too, beside its successor.
                let mut kept: Vec<Vec<u8>> = managed_kept.iter().map(|id| id.to_vec()).collect();
                kept.push(b"retired".to_vec());
                (
                    damage,
                    Membership::Rebuilt,
                    kept,
                    vec![("user 4", 2)],
                    moved,
                )
            }
            Scenario::Marker | Scenario::MarkerOnly => {
                let mut damage = vec![corrupt(FORMAT_FILE.into())];
                let mut moved = vec![FORMAT_FILE.to_owned()];
                let kept = if scenario == Scenario::Marker {
                    damage.push(corrupt(file_of(b"third", &records)));
                    moved.push(active.clone());
                    moved.push(file_of(b"third", &records));
                    moved.push(file_of(b"retired", &records));
                    without(&managed_kept, b"third")
                } else {
                    managed_kept.iter().map(|id| id.to_vec()).collect()
                };
                (damage, Membership::Kept, kept, vec![], moved)
            }
            Scenario::Namespace => (
                vec![
                    Damage::missing(MANAGED_DIR),
                    Damage::missing(CREDENTIALS_DIR),
                ],
                Membership::Created(MANAGED_DIR.into()),
                vec![],
                vec![],
                vec![],
            ),
            Scenario::LegacyDirectory => (
                vec![Damage::missing(CREDENTIALS_DIR)],
                Membership::Created(CREDENTIALS_DIR.into()),
                vec![],
                vec![],
                vec![],
            ),
        };
        moved.sort();
        let context = format!("{scenario:?}");
        assert_eq!(plan.damage, damage, "{context}");
        assert_eq!(plan.membership, membership, "{context}");
        assert_eq!(
            plan.shared,
            shared
                .iter()
                .map(|&(user, passkeys)| Account {
                    rp_id: RP.into(),
                    user_name: Some(user.into()),
                    user_display_name: None,
                    passkeys,
                })
                .collect::<Vec<_>>(),
            "{context}"
        );
        assert_eq!(plan.max_credentials, DEFAULT_MAX_CREDENTIALS, "{context}");
        assert_eq!(plan.moved, moved, "{context}");
        let discoverable = kept
            .iter()
            .filter(|id| crate::credential_id::is_discoverable(id))
            .count();
        assert_eq!(
            (plan.passkeys, plan.others),
            (discoverable, kept.len() - discoverable),
            "{context}"
        );
        assert_eq!(
            plan.marker,
            matches!(
                scenario,
                Scenario::Marker
                    | Scenario::MarkerOnly
                    | Scenario::MarkerAndManifest
                    | Scenario::Legacy
            ),
            "{context}"
        );
        // The inspection's damage comes first.
        let inspected = FileStore::inspect_in(&state).unwrap();
        assert_eq!(plan.damage[..inspected.len()], inspected[..], "{context}");

        let before = files(&state);
        let repaired = FileStore::repair_in(&state, &plan).unwrap();
        assert_eq!(repaired.durability, CommitDurability::Flushed, "{context}");
        assert!(!repaired.cleanup_pending, "{context}");
        match &repaired.quarantine {
            None => assert!(moved.is_empty(), "{context}"),
            Some(quarantine) => {
                assert_eq!(
                    quarantine.parent().unwrap(),
                    state.join(QUARANTINE),
                    "{context}"
                );
                let held = files(quarantine);
                for file in &moved {
                    let path = PathBuf::from(file);
                    match before.get(&path) {
                        // Byte for byte what the store had.
                        Some(original) => {
                            assert_eq!(held.get(&path), Some(original), "{context}: {file}");
                        }
                        None => assert!(quarantine.join(file).is_dir(), "{context}: {file}"),
                    }
                }
                // Nothing else is in it.
                let expected: BTreeSet<_> = moved
                    .iter()
                    .map(PathBuf::from)
                    .filter(|path| before.contains_key(path))
                    .chain(Some(PathBuf::from(format!("{active}/left"))))
                    .collect();
                assert!(
                    held.keys().all(|path| expected.contains(path)),
                    "{context}: {held:?}"
                );
            }
        }
        assert_untouched(&before, &state, &context);
        assert_eq!(FileStore::inspect_in(&state).unwrap(), [], "{context}");
        let store = FileStore::open(&state).unwrap();
        let listed: BTreeSet<Vec<u8>> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|record| record.credential_id.clone())
            .collect();
        assert_eq!(listed, kept.iter().cloned().collect(), "{context}");
        let names: BTreeSet<String> = kept.iter().map(|id| name_of(id)).collect();
        if let Ok(Some(manifest)) = store.membership(&keys).unwrap() {
            assert_eq!(
                manifest.keys().cloned().collect::<BTreeSet<_>>(),
                names,
                "{context}"
            );
        }
        // Nothing the store does not list is left in its record
        // directories, so no later cleanup has anything to remove; except
        // where repair publishes no list, which leaves what cleanup left as
        // it was, for the next commit.
        let left: BTreeSet<String> = if scenario == Scenario::MarkerOnly {
            BTreeSet::from([name_of(b"retired")])
        } else {
            BTreeSet::new()
        };
        for location in [Location::Legacy, Location::Managed] {
            for name in repair::record_files(&store.record_dir(location)).unwrap() {
                assert!(
                    names.contains(&name) || left.contains(&name),
                    "{context}: {name}"
                );
            }
        }
        // It takes registrations again.
        let mut app = CtapApp::with_file_store(store, AutoApprove, &INTERRUPT, [0; 16]);
        assert_eq!(register(&mut app), CTAP2_OK, "{context}");
        drop(app);
        // And there is nothing more to repair.
        assert_eq!(
            FileStore::plan_repair_in(&state).unwrap(),
            None,
            "{context}"
        );
    }
}

fn int(value: i64) -> ciborium::value::Value {
    ciborium::value::Value::Integer(value.into())
}

fn text(value: &str) -> ciborium::value::Value {
    ciborium::value::Value::Text(value.into())
}

fn ctap(
    app: &mut CtapApp<'_>,
    command: u8,
    fields: Vec<(ciborium::value::Value, ciborium::value::Value)>,
) -> Vec<u8> {
    let mut request = vec![command];
    ciborium::ser::into_writer(&ciborium::value::Value::Map(fields), &mut request).unwrap();
    app.call(&request)
}

/// makeCredential for a new ES256 passkey on [`RP`]: the status.
fn register(app: &mut CtapApp<'_>) -> u8 {
    use ciborium::value::Value;
    ctap(
        app,
        CTAP_CMD_MAKE_CREDENTIAL,
        vec![
            (int(1), Value::Bytes(vec![0x11; 32])),
            (int(2), Value::Map(vec![(text("id"), text(RP))])),
            (
                int(3),
                Value::Map(vec![(text("id"), Value::Bytes(vec![0x77; 16]))]),
            ),
            (
                int(4),
                Value::Array(vec![Value::Map(vec![
                    (text("alg"), int(-7)),
                    (text("type"), text("public-key")),
                ])]),
            ),
            (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))])),
        ],
    )[0]
}

/// The signature counter of an assertion with `id` on [`RP`].
fn assertion_counter(app: &mut CtapApp<'_>, id: &[u8]) -> u32 {
    use ciborium::value::Value;
    let response = ctap(
        app,
        CTAP_CMD_GET_ASSERTION,
        vec![
            (int(1), text(RP)),
            (int(2), Value::Bytes(vec![0x22; 32])),
            (
                int(3),
                Value::Array(vec![Value::Map(vec![
                    (text("id"), Value::Bytes(id.to_vec())),
                    (text("type"), text("public-key")),
                ])]),
            ),
        ],
    );
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(fields) = ciborium::de::from_reader(&response[1..]).unwrap() else {
        panic!("not a map");
    };
    let Some((_, Value::Bytes(data))) = fields.into_iter().find(|(key, _)| *key == int(2)) else {
        panic!("no authenticator data");
    };
    u32::from_be_bytes(data[33..37].try_into().unwrap())
}

/// A rebuild keeps every record that authenticates, whatever its creation
/// order: a passkey a deletion left behind with an order above that of its
/// account's passkey, passkeys of one account with the same order, and
/// stored credentials that are not discoverable, which share an empty user
/// handle.  The plan names each account it keeps more than one passkey of,
/// and nothing is moved but the manifest.
#[test]
fn a_rebuild_keeps_every_record_that_authenticates() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let mut store = FileStore::open(&state).unwrap();
    store
        .insert_or_replace_discoverable(&passkey(b"first", 1))
        .unwrap();
    store.put(&security_key(0x61)).unwrap();
    store.put(&security_key(0x62)).unwrap();
    plant(&store, &passkey(b"tied a", 2), 50, Location::Managed);
    plant(&store, &passkey(b"tied b", 2), 50, Location::Managed);
    plant(&store, &passkey(b"lower", 2), 49, Location::Managed);
    plant(&store, &passkey(b"deleted", 1), 90, Location::Managed);
    flip_last_byte(&state.join(MANAGED_DIR).join(ACTIVE_FILE));
    let plan = FileStore::plan_repair_in(&state).unwrap().unwrap();
    assert_eq!(plan.membership, Membership::Rebuilt);
    assert_eq!((plan.passkeys, plan.others), (5, 2));
    let account = |user: u8, passkeys| Account {
        rp_id: RP.into(),
        user_name: Some(format!("user {user}")),
        user_display_name: None,
        passkeys,
    };
    assert_eq!(plan.shared, [account(1, 2), account(2, 3)]);
    assert_eq!(plan.moved, [format!("{MANAGED_DIR}/{ACTIVE_FILE}")]);
    FileStore::repair_in(&state, &plan).unwrap();
    let mut listed: Vec<_> = store
        .list()
        .unwrap()
        .into_iter()
        .map(|record| record.credential_id.clone())
        .collect();
    listed.sort();
    let mut kept = vec![
        b"first".to_vec(),
        b"deleted".to_vec(),
        b"tied a".to_vec(),
        b"tied b".to_vec(),
        b"lower".to_vec(),
        security_key(0x61).credential_id.clone(),
        security_key(0x62).credential_id.clone(),
    ];
    kept.sort();
    assert_eq!(listed, kept);
}

/// Accounts are told apart by site and user handle: one user handle on two
/// sites is two accounts, and so are two user handles on one site.  The
/// plan names each account the new list holds more than one passkey of, by
/// site and then user handle.
#[test]
fn a_rebuild_names_each_account_by_site_and_user_handle() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let mut store = FileStore::open(&state).unwrap();
    let on = |site: &str, id: &[u8], user: u8| {
        let mut record = passkey(id, user);
        record.rp_id = site.into();
        record
    };
    store
        .insert_or_replace_discoverable(&on("a.example", b"a2", 2))
        .unwrap();
    for (site, id, user, created_at) in [
        ("a.example", b"a2 again".as_slice(), 2, 10),
        ("a.example", b"a1", 1, 11),
        ("b.example", b"b1", 1, 12),
        ("b.example", b"b1 again", 1, 13),
        ("b.example", b"b2", 2, 14),
    ] {
        plant(&store, &on(site, id, user), created_at, Location::Managed);
    }
    flip_last_byte(&state.join(MANAGED_DIR).join(ACTIVE_FILE));
    let plan = FileStore::plan_repair_in(&state).unwrap().unwrap();
    assert_eq!(plan.membership, Membership::Rebuilt);
    assert_eq!((plan.passkeys, plan.others), (6, 0));
    let account = |site: &str, user: u8| Account {
        rp_id: site.into(),
        user_name: Some(format!("user {user}")),
        user_display_name: None,
        passkeys: 2,
    };
    assert_eq!(
        plan.shared,
        [account("a.example", 2), account("b.example", 1)]
    );
}

/// What a repair reports when a flush after its publication fails, or its
/// cleanup does: the flush as unconfirmed durability, and the cleanup as
/// pending, with the records the new list does not name still in place as
/// well as in the quarantine.  A later change to the list removes them, and
/// neither it nor a reset touches the quarantine.
#[test]
fn a_repair_reports_a_failed_flush_or_cleanup_and_a_later_change_cleans_up() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    Scenario::Record.apply(&state);
    let planned = plan(&state);
    let repaired = without_cleanup(|| FileStore::repair_in(&state, &planned)).unwrap();
    assert_eq!(repaired.durability, CommitDurability::Flushed);
    assert!(repaired.cleanup_pending);
    let quarantine = repaired.quarantine.unwrap();
    let held = files(&quarantine);
    let records: Vec<&String> = planned
        .moved
        .iter()
        .filter(|moved| moved.starts_with(&format!("{MANAGED_DIR}/{RECORDS_DIR}/")))
        .collect();
    assert_eq!(records.len(), 2, "the damaged record and the retired one");
    for record in &records {
        assert_eq!(
            Some(&fs::read(state.join(record)).unwrap()),
            held.get(&PathBuf::from(record)),
            "{record}: in place, and in the quarantine"
        );
    }
    assert_eq!(FileStore::inspect_in(&state).unwrap(), []);
    let mut store = FileStore::open(&state).unwrap();
    store
        .insert_or_replace_discoverable(&passkey(b"later", 9))
        .unwrap();
    for record in &records {
        assert!(!state.join(record).exists(), "{record}: removed");
    }
    assert_eq!(files(&quarantine), held, "after a later change");
    store.clear().unwrap();
    assert_eq!(files(&quarantine), held, "after a reset");

    // The flush after the new list, or after the format marker written
    // again, fails: the repair is visible, with unconfirmed durability.
    for (scenario, published, file) in [
        (Scenario::Manifest, "published", ACTIVE_FILE),
        (Scenario::MarkerOnly, "renamed", FORMAT_FILE),
    ] {
        let scratch = TempDir::new();
        let state = scratch.path().join("state");
        scenario.apply(&state);
        let planned = plan(&state);
        let mut armed = false;
        let repaired = fsio::with_hook(
            Box::new(move |event, path| {
                if event == published && path.ends_with(file) {
                    armed = true;
                } else if armed && event == "directory-flush" {
                    armed = false;
                    return Err(fsio::io_error(path, std::io::Error::other("flush fails")));
                }
                Ok(())
            }),
            || FileStore::repair_in(&state, &planned),
        )
        .unwrap();
        assert_eq!(
            repaired.durability,
            CommitDurability::Unconfirmed,
            "{scenario:?}"
        );
        assert_eq!(FileStore::inspect_in(&state).unwrap(), [], "{scenario:?}");
    }
}

/// The status of getAssertion on [`RP`] with `id` in its allow list.
fn sign_in(app: &mut CtapApp<'_>, id: &[u8]) -> u8 {
    use ciborium::value::Value;
    ctap(
        app,
        CTAP_CMD_GET_ASSERTION,
        vec![
            (int(1), text(RP)),
            (int(2), Value::Bytes(vec![0x22; 32])),
            (
                int(3),
                Value::Array(vec![Value::Map(vec![
                    (text("id"), Value::Bytes(id.to_vec())),
                    (text("type"), text("public-key")),
                ])]),
            ),
        ],
    )[0]
}

/// makeCredential for a passkey of the account `user` on [`RP`]: the
/// status.
fn register_account(app: &mut CtapApp<'_>, user: u8) -> u8 {
    use ciborium::value::Value;
    ctap(
        app,
        CTAP_CMD_MAKE_CREDENTIAL,
        vec![
            (int(1), Value::Bytes(vec![0x11; 32])),
            (int(2), Value::Map(vec![(text("id"), text(RP))])),
            (
                int(3),
                Value::Map(vec![(text("id"), Value::Bytes(vec![user]))]),
            ),
            (
                int(4),
                Value::Array(vec![Value::Map(vec![
                    (text("alg"), int(-7)),
                    (text("type"), text("public-key")),
                ])]),
            ),
            (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))])),
        ],
    )[0]
}

/// The passkeys of the account `user` that `store` holds.
fn passkeys_of(store: &FileStore, user: u8) -> Vec<Vec<u8>> {
    store
        .list()
        .unwrap()
        .into_iter()
        .filter(|record| record.user_id == [user])
        .map(|record| record.credential_id.clone())
        .collect()
}

/// The verifier's first probe: a passkey deleted while it had the store's
/// highest creation order, whose record was left behind, outranks the one
/// its account registered after it.  A rebuild keeps both: the passkey the
/// site knows signs, and so does the other; the plan names the account; and
/// the account's next registration replaces both.
#[test]
fn a_deleted_passkey_left_behind_does_not_take_the_place_of_its_accounts_own() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let mut store = FileStore::open(&state).unwrap();
    store
        .insert_or_replace_discoverable(&passkey(b"q", 7))
        .unwrap();
    store
        .insert_or_replace_discoverable(&passkey(b"x", 1))
        .unwrap();
    let x = record_file(&store, b"x");
    let contents = fs::read(&x).unwrap();
    assert!(store.delete(b"x").unwrap());
    assert!(store.delete(b"q").unwrap());
    store
        .insert_or_replace_discoverable(&passkey(b"y", 1))
        .unwrap();
    // Left behind, as by a restore, after the last commit, whose cleanup
    // would remove it again.
    fs::write(&x, contents).unwrap();
    assert!(
        store.get(b"y").unwrap().unwrap().created_at < codec_order(&store, &x),
        "the deleted record outranks the passkey in use"
    );
    flip_last_byte(&state.join(MANAGED_DIR).join(ACTIVE_FILE));
    let plan = FileStore::plan_repair_in(&state).unwrap().unwrap();
    assert_eq!(plan.shared.len(), 1);
    assert_eq!(
        (plan.shared[0].user_name.as_deref(), plan.shared[0].passkeys),
        (Some("user 1"), 2)
    );
    FileStore::repair_in(&state, &plan).unwrap();
    let mut held = passkeys_of(&store, 1);
    held.sort();
    assert_eq!(held, [b"x".to_vec(), b"y".to_vec()]);
    let mut app = CtapApp::with_file_store(
        FileStore::open(&state).unwrap(),
        AutoApprove,
        &INTERRUPT,
        [0; 16],
    );
    assert_eq!(
        sign_in(&mut app, b"y"),
        CTAP2_OK,
        "the passkey in use signs"
    );
    assert_eq!(sign_in(&mut app, b"x"), CTAP2_OK);
    assert_eq!(register_account(&mut app, 1), CTAP2_OK);
    for id in [b"x", b"y"] {
        assert_eq!(sign_in(&mut app, id), CTAP2_ERR_NO_CREDENTIALS, "replaced");
    }
    drop(app);
    assert_eq!(passkeys_of(&FileStore::open(&state).unwrap(), 1).len(), 1);
}

/// The creation order of the record in `file`, read with the store's key.
fn codec_order(store: &FileStore, file: &Path) -> u64 {
    let keys = store.credential_keys().unwrap().unwrap();
    let name = file.file_name().unwrap().to_str().unwrap();
    store
        .read_credential_in(&keys, name, file.parent().unwrap(), Location::Managed)
        .unwrap()
        .unwrap()
        .created_at
}

/// The verifier's second probe: a registration of an account that failed
/// after it wrote its record, but before it published the list naming it,
/// leaves a record the site never received, which outranks the account's
/// passkey.  A rebuild keeps both: the account's passkey signs, and deleting
/// the other leaves it signing.
#[test]
fn a_failed_registration_does_not_take_the_place_of_its_accounts_passkey() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let mut store = FileStore::open(&state).unwrap();
    store
        .insert_or_replace_discoverable(&passkey(b"aa", 1))
        .unwrap();
    let failed = fsio::with_hook(
        Box::new(|event, path| {
            if event == "publication" {
                Err(fsio::io_error(path, std::io::Error::other("interrupted")))
            } else {
                Ok(())
            }
        }),
        || store.insert_or_replace_discoverable(&passkey(b"bb", 1)),
    );
    assert!(failed.is_err());
    assert_eq!(store.get(b"bb").unwrap(), None, "never published");
    flip_last_byte(&state.join(MANAGED_DIR).join(ACTIVE_FILE));
    let plan = FileStore::plan_repair_in(&state).unwrap().unwrap();
    assert_eq!(
        plan.shared,
        [Account {
            rp_id: RP.into(),
            user_name: Some("user 1".into()),
            user_display_name: None,
            passkeys: 2,
        }]
    );
    FileStore::repair_in(&state, &plan).unwrap();
    let mut app = CtapApp::with_file_store(
        FileStore::open(&state).unwrap(),
        AutoApprove,
        &INTERRUPT,
        [0; 16],
    );
    assert_eq!(
        sign_in(&mut app, b"aa"),
        CTAP2_OK,
        "the passkey in use signs"
    );
    assert_eq!(sign_in(&mut app, b"bb"), CTAP2_OK);
    drop(app);
    assert!(FileStore::open(&state).unwrap().delete(b"bb").unwrap());
    let mut app = CtapApp::with_file_store(
        FileStore::open(&state).unwrap(),
        AutoApprove,
        &INTERRUPT,
        [0; 16],
    );
    assert_eq!(sign_in(&mut app, b"aa"), CTAP2_OK);
    assert_eq!(sign_in(&mut app, b"bb"), CTAP2_ERR_NO_CREDENTIALS);
}

/// A rebuild keeps every record that authenticates even when they are more
/// than the store's limit, which the plan reports: then a registration that
/// adds a credential, a passkey of a new account or a security key's
/// stored credential, is refused until the store holds fewer than its
/// limit, while one that replaces an account's passkeys is not.
#[test]
fn a_rebuild_above_the_credential_limit_keeps_every_record() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let mut store = FileStore::open(&state).unwrap().with_max_credentials(2);
    store
        .insert_or_replace_discoverable(&passkey(b"one", 1))
        .unwrap();
    store
        .insert_or_replace_discoverable(&passkey(b"two", 2))
        .unwrap();
    plant(&store, &passkey(b"three", 3), 9, Location::Managed);
    flip_last_byte(&state.join(MANAGED_DIR).join(ACTIVE_FILE));
    let plan = store.plan_repair().unwrap().unwrap();
    assert_eq!(
        (plan.passkeys, plan.others, plan.max_credentials),
        (3, 0, 2)
    );
    store.repair(&plan).unwrap();
    assert_eq!(store.count().unwrap(), 3);
    assert!(matches!(
        store.put(&security_key(0x71)),
        Err(StoreError::Full { max: 2 })
    ));
    let mut app = CtapApp::with_file_store(store, AutoApprove, &INTERRUPT, [0; 16]);
    assert_eq!(register_account(&mut app, 4), CTAP2_ERR_KEY_STORE_FULL);
    assert_eq!(
        register_account(&mut app, 3),
        CTAP2_OK,
        "a replacement adds none"
    );
    drop(app);
    let mut store = FileStore::open(&state).unwrap().with_max_credentials(2);
    // 3 held, room for 2: one more needs two deleted.
    assert!(store.delete(b"one").unwrap());
    assert!(matches!(
        store.put(&security_key(0x71)),
        Err(StoreError::Full { max: 2 })
    ));
    let mut app = CtapApp::with_file_store(store, AutoApprove, &INTERRUPT, [0; 16]);
    assert_eq!(register_account(&mut app, 4), CTAP2_ERR_KEY_STORE_FULL);
    drop(app);
    let mut store = FileStore::open(&state).unwrap().with_max_credentials(2);
    assert!(store.delete(b"two").unwrap());
    let mut app = CtapApp::with_file_store(store, AutoApprove, &INTERRUPT, [0; 16]);
    assert_eq!(register_account(&mut app, 4), CTAP2_OK);
}

/// Repair never makes a counter go back: kept records keep theirs, the
/// shared one of sealed credentials is left alone, and of two authentic
/// copies of one credential, in both record directories, a rebuild keeps
/// the one with the higher counter, in either directory.
#[test]
fn counters_never_go_back() {
    for higher in [Location::Legacy, Location::Managed] {
        let scratch = TempDir::new();
        let state = scratch.path().join("state");
        let mut store = FileStore::open(&state).unwrap();
        let mut used = passkey(b"used", 1);
        used.sign_count = 1000;
        store.put(&used).unwrap();
        store
            .insert_or_replace_discoverable(&passkey(b"other", 2))
            .unwrap();
        store.set_signature_counter(5000).unwrap();
        let sealed = store.seal_credential_id(&[0x33; 66], b"rp hash").unwrap();
        // The migrated record's copy among the managed ones, with a lower or
        // a higher counter.
        let mut copy = used.clone();
        copy.sign_count = if higher == Location::Managed {
            2000
        } else {
            900
        };
        plant(&store, &copy, 1, Location::Managed);
        flip_last_byte(&state.join(MANAGED_DIR).join(ACTIVE_FILE));
        let plan = FileStore::plan_repair_in(&state).unwrap().unwrap();
        FileStore::repair_in(&state, &plan).unwrap();
        let expected = if higher == Location::Managed {
            2000
        } else {
            1000
        };
        assert_eq!(
            store.get(b"used").unwrap().unwrap().sign_count,
            expected,
            "{higher:?}"
        );
        assert_eq!(store.signature_counter().unwrap(), 5000);
        assert!(
            store
                .open_credential_id(&sealed, b"rp hash")
                .unwrap()
                .is_some()
        );
        let mut app = CtapApp::with_file_store(store, AutoApprove, &INTERRUPT, [0; 16]);
        assert_eq!(
            assertion_counter(&mut app, b"used"),
            expected + 1,
            "{higher:?}"
        );
    }
    // Members a repair keeps keep their counters too.
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    Scenario::Record.apply(&state);
    let plan = FileStore::plan_repair_in(&state).unwrap().unwrap();
    FileStore::repair_in(&state, &plan).unwrap();
    let store = FileStore::open(&state).unwrap();
    assert_eq!(store.get(b"kept").unwrap().unwrap().sign_count, 7);
    assert_eq!(store.get(b"second").unwrap().unwrap().sign_count, 7);
    assert_eq!(store.signature_counter().unwrap(), 500);
}

/// A plan is carried out only on the store it was made for: a store that
/// changed since is left as it is.  A healthy store has nothing to repair,
/// and planning creates nothing, not even a missing state directory.
#[test]
fn repair_does_only_what_was_planned_and_healthy_stores_need_none() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    Scenario::Record.apply(&state);
    let plan = FileStore::plan_repair_in(&state).unwrap().unwrap();
    let store = FileStore::unopened(&state);
    flip_last_byte(&record_file(&store, b"second"));
    let before = files(&state);
    let err = FileStore::repair_in(&state, &plan).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "{}: it changed after its repair was planned",
            state.display()
        )
    );
    assert_eq!(files(&state), before);
    assert!(!state.join(QUARANTINE).exists());

    let missing = scratch.path().join("missing");
    assert_eq!(FileStore::plan_repair_in(&missing).unwrap(), None);
    assert!(!missing.exists());
    let healthy = scratch.path().join("healthy");
    let mut store = FileStore::open(&healthy).unwrap();
    for step in 0..3 {
        if step == 1 {
            store.put(&passkey(b"legacy", 1)).unwrap();
        } else if step == 2 {
            store
                .insert_or_replace_discoverable(&passkey(b"managed", 2))
                .unwrap();
        }
        let before = files(&healthy);
        assert_eq!(FileStore::plan_repair_in(&healthy).unwrap(), None, "{step}");
        assert_eq!(files(&healthy), before, "{step}");
    }
}
