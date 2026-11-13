//! Repair of damaged credential sets: what it keeps, what it sets aside, and
//! errors and process exits at every checkpoint.

#![expect(
    clippy::disallowed_methods,
    reason = "tests damage, copy and remove store files directly, outside the store's wrappers"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    /// The shared signature counter fails authentication, and nothing else.
    Counter,
    /// A copy of the migrated passkey `kept` among the managed records, as
    /// a writer outside this code could leave it, has counted higher and
    /// fails authentication; so do the manifest and the shared counter.
    Copies,
    /// A symbolic link to itself in the shared counter's place, which fails
    /// reads with ELOOP.
    CounterLinkLoop,
    /// A symbolic link to the directory `keys` in the shared counter's
    /// place, which fails reads with EISDIR.
    CounterLinkToDirectory,
    /// An empty file in the shared counter's place, as repair's refusal of a
    /// directory there says to create: it fails authentication by its length.
    EmptyCounter,
}

impl Scenario {
    pub(super) const ALL: [Self; 16] = [
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
        Self::Counter,
        Self::Copies,
        Self::CounterLinkLoop,
        Self::CounterLinkToDirectory,
        Self::EmptyCounter,
    ];

    /// Whether repair writes the shared counter again.
    fn rebuilds_counter(self) -> bool {
        self == Self::Copies || self.counter_alone()
    }

    /// Whether the shared counter is damaged, and nothing else.
    fn counter_alone(self) -> bool {
        matches!(
            self,
            Self::Counter
                | Self::CounterLinkLoop
                | Self::CounterLinkToDirectory
                | Self::EmptyCounter
        )
    }

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
            Self::Counter => flip_last_byte(&state.join(SIGNATURE_COUNTER_FILE)),
            Self::Copies => {
                let mut copy = passkey(b"kept", 1);
                copy.sign_count = 2000;
                plant(&store, &copy, 1, Location::Managed);
                let keys = store.credential_keys().unwrap().unwrap();
                let name = keys.file_name(b"kept").unwrap();
                flip_last_byte(&set.join(RECORDS_DIR).join(name));
                flip_last_byte(&set.join(ACTIVE_FILE));
                flip_last_byte(&state.join(SIGNATURE_COUNTER_FILE));
            }
            Self::CounterLinkLoop | Self::CounterLinkToDirectory => {
                let counter = state.join(SIGNATURE_COUNTER_FILE);
                fs::remove_file(&counter).unwrap();
                let target = if self == Self::CounterLinkLoop {
                    SIGNATURE_COUNTER_FILE
                } else {
                    KEYS_DIR
                };
                std::os::unix::fs::symlink(target, &counter).unwrap();
            }
            Self::EmptyCounter => fs::write(state.join(SIGNATURE_COUNTER_FILE), b"").unwrap(),
        }
        if matches!(self, Self::Marker | Self::MarkerOnly) {
            flip_last_byte(&state.join(FORMAT_FILE));
        }
    }
}

/// What a store serves: its credentials, and its shared counter, which
/// repair writes on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Served {
    credentials: Credentials,
    /// The shared counter, or `None` if it cannot be read.
    counter: Option<u32>,
}

/// The credentials a store serves: none at all, or those it lists, with
/// their counters, and for a managed store its members.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Credentials {
    Unavailable,
    Legacy(Vec<(Vec<u8>, u32)>),
    Managed(Vec<(Vec<u8>, u32)>, BTreeSet<String>),
}

/// How [`served`] shows a count that repair wrote from the clock, which is
/// not the same from one repair to the next.
const FROM_THE_CLOCK: u32 = u32::MAX;

/// `count`, or [`FROM_THE_CLOCK`] if repair wrote it: these tests count no
/// higher than a few thousand.
fn shown(count: u32) -> u32 {
    if count >= 1_000_000_000 {
        FROM_THE_CLOCK
    } else {
        count
    }
}

fn served(state: &Path) -> Served {
    let store = FileStore::unopened(state);
    let keys = store.credential_keys().unwrap().unwrap();
    let listed = || {
        let mut listed: Vec<_> = store
            .list()
            .unwrap()
            .iter()
            .map(|record| (record.credential_id.clone(), shown(record.sign_count)))
            .collect();
        listed.sort();
        listed
    };
    let credentials = match store.membership(&keys).unwrap() {
        Err(_) => Credentials::Unavailable,
        Ok(None) => Credentials::Legacy(listed()),
        Ok(Some(manifest)) => Credentials::Managed(listed(), manifest.into_keys().collect()),
    };
    Served {
        credentials,
        counter: store.counter(&keys).ok().map(shown),
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

/// A copy of `from`, every file and directory, at `to`, with each symbolic
/// link copied as a link: those these tests make point by relative names.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        let target = to.join(path.file_name().unwrap());
        let metadata = fs::symlink_metadata(&path).unwrap();
        if metadata.file_type().is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(&path).unwrap(), &target).unwrap();
        } else if metadata.is_dir() {
            copy_tree(&path, &target);
        } else {
            fs::copy(&path, &target).unwrap();
        }
    }
}

/// Every symbolic link under `dir`, by its path relative to `dir`, with
/// what it points to.
fn links(dir: &Path) -> BTreeMap<PathBuf, PathBuf> {
    let mut found = BTreeMap::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(current) = dirs.pop() {
        for entry in fs::read_dir(&current).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                dirs.push(path);
            } else if metadata.file_type().is_symlink() {
                found.insert(
                    path.strip_prefix(dir).unwrap().to_path_buf(),
                    fs::read_link(&path).unwrap(),
                );
            }
        }
    }
    found
}

/// Every symbolic link of `before` is still in `state`, pointing where it
/// did: where it was, or in a quarantine at its relative path.
#[track_caller]
fn assert_no_link_lost(before: &BTreeMap<PathBuf, PathBuf>, state: &Path, context: &str) {
    let after = links(state);
    for (path, points_to) in before {
        let kept = after.iter().any(|(other, held)| {
            held == points_to
                && (other == path || other.starts_with(QUARANTINE) && other.ends_with(path))
        });
        assert!(kept, "{context}: the link {} was lost", path.display());
    }
}

/// The shared counter of the store in `state`, `None` if it cannot be read,
/// and the counter of each credential it lists, as they are, unlike
/// [`served`] shows them.
fn counts(state: &Path) -> (Option<u32>, BTreeMap<Vec<u8>, u32>) {
    let store = FileStore::unopened(state);
    let keys = store.credential_keys().unwrap().unwrap();
    let listed = store
        .list()
        .map(|records| {
            records
                .iter()
                .map(|record| (record.credential_id.clone(), record.sign_count))
                .collect()
        })
        .unwrap_or_default();
    (store.counter(&keys).ok(), listed)
}

/// No count of `before` is higher than the same count `after`: the shared
/// counter, and each credential's.
#[track_caller]
fn assert_no_count_lower(
    before: &(Option<u32>, BTreeMap<Vec<u8>, u32>),
    after: &(Option<u32>, BTreeMap<Vec<u8>, u32>),
    context: &str,
) {
    if let Some(shared) = before.0 {
        assert!(
            after.0.is_some_and(|now| now >= shared),
            "{context}: the shared counter went from {shared} to {:?}",
            after.0
        );
    }
    for (id, count) in &before.1 {
        if let Some(now) = after.1.get(id) {
            assert!(now >= count, "{context}: {id:?} went from {count} to {now}");
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

/// The files repair never touches, and the shared counter, unless repair
/// writes it again in `scenario`.
#[track_caller]
fn assert_untouched(
    before: &BTreeMap<PathBuf, Vec<u8>>,
    state: &Path,
    scenario: Scenario,
    context: &str,
) {
    let after = files(state);
    for path in [PIN_STATE_FILE, LARGE_BLOBS_FILE, ATTESTATION_FILE]
        .into_iter()
        .chain((!scenario.rebuilds_counter()).then_some(SIGNATURE_COUNTER_FILE))
        .map(PathBuf::from)
        .chain(
            before
                .keys()
                .filter(|path| path.starts_with(KEYS_DIR))
                .cloned(),
        )
    {
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
    scenario: Scenario,
    state: PathBuf,
    before: BTreeMap<PathBuf, Vec<u8>>,
    before_links: BTreeMap<PathBuf, PathBuf>,
    old: Served,
    repaired: Served,
}

impl Template {
    fn new(scenario: Scenario) -> Self {
        let scratch = TempDir::new();
        let state = scratch.path().join("template");
        scenario.apply(&state);
        let before = files(&state);
        let before_links = links(&state);
        let old = served(&state);
        let copy = scratch.path().join("repaired");
        copy_tree(&state, &copy);
        FileStore::repair_in(&copy, &plan(&copy)).unwrap();
        let repaired = served(&copy);
        assert_ne!(old, repaired, "{scenario:?}: repair changes what is served");
        Self {
            _scratch: scratch,
            scenario,
            state,
            before,
            before_links,
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

    /// After a repair that failed or crashed: the store serves the
    /// credentials it served or those repair makes it serve, and its counter
    /// is as it was or as repair writes it, never missing, and named by the
    /// inspection until it is written again; every file and link is where
    /// it was or in a quarantine; and repairing again finishes the work
    /// without lowering any count.  Returns whether the store served what
    /// repair makes it serve already.
    #[track_caller]
    fn assert_recovers(&self, state: &Path, context: &str) -> bool {
        let now = served(state);
        assert!(
            now.credentials == self.old.credentials || now.credentials == self.repaired.credentials,
            "{context}: serves {now:?}"
        );
        assert!(
            now.counter == self.old.counter || now.counter == self.repaired.counter,
            "{context}: counts {now:?}"
        );
        if self.scenario.rebuilds_counter() {
            assert!(
                fs::symlink_metadata(state.join(SIGNATURE_COUNTER_FILE)).is_ok(),
                "{context}: the counter is missing"
            );
            if now.counter == self.old.counter {
                assert!(
                    FileStore::inspect_in(state)
                        .unwrap()
                        .iter()
                        .any(|damage| damage.file == SIGNATURE_COUNTER_FILE),
                    "{context}: the damaged counter is not reported"
                );
            }
        }
        assert_nothing_lost(&self.before, state, context);
        assert_no_link_lost(&self.before_links, state, context);
        assert_untouched(&self.before, state, self.scenario, context);
        let counted = counts(state);
        if let Some(plan) = FileStore::plan_repair_in(state).unwrap() {
            FileStore::repair_in(state, &plan)
                .unwrap_or_else(|err| panic!("{context}: repairing again: {err}"));
        }
        assert_eq!(served(state), self.repaired, "{context}");
        assert_eq!(FileStore::inspect_in(state).unwrap(), [], "{context}");
        assert_nothing_lost(&self.before, state, context);
        assert_no_link_lost(&self.before_links, state, context);
        assert_no_count_lower(&counted, &counts(state), context);
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
            Scenario::Counter => (
                vec![corrupt(SIGNATURE_COUNTER_FILE.into())],
                Membership::Intact,
                managed_kept.iter().map(|id| id.to_vec()).collect(),
                vec![],
                vec![SIGNATURE_COUNTER_FILE.to_owned()],
            ),
            Scenario::Copies => {
                // The authentic copy of `kept` is kept, and so is the
                // passkey a registration of account 4 replaced.
                let mut kept: Vec<Vec<u8>> = managed_kept.iter().map(|id| id.to_vec()).collect();
                kept.push(b"retired".to_vec());
                (
                    vec![
                        corrupt(SIGNATURE_COUNTER_FILE.into()),
                        corrupt(active.clone()),
                        corrupt(file_of(b"kept", &records)),
                    ],
                    Membership::Rebuilt,
                    kept,
                    vec![("user 4", 2)],
                    vec![
                        active.clone(),
                        SIGNATURE_COUNTER_FILE.to_owned(),
                        file_of(b"kept", &records),
                        file_of(b"kept", MANAGED_DIR),
                    ],
                )
            }
            Scenario::CounterLinkLoop
            | Scenario::CounterLinkToDirectory
            | Scenario::EmptyCounter => {
                let path = state.join(SIGNATURE_COUNTER_FILE);
                let fault = if scenario == Scenario::EmptyCounter {
                    Fault::Corrupt(Corruption::Length)
                } else {
                    let err = fs::read(&path).unwrap_err();
                    Fault::Unreadable(format!("{}: {err}", path.display()))
                };
                (
                    vec![Damage {
                        file: SIGNATURE_COUNTER_FILE.into(),
                        fault,
                    }],
                    Membership::Intact,
                    managed_kept.iter().map(|id| id.to_vec()).collect(),
                    vec![],
                    vec![SIGNATURE_COUNTER_FILE.to_owned()],
                )
            }
        };
        moved.sort();
        let context = format!("{scenario:?}");
        assert_eq!(plan.damage, damage, "{context}");
        assert_eq!(plan.membership, membership, "{context}");
        assert_eq!(plan.counter, scenario.rebuilds_counter(), "{context}");
        let raised = if scenario == Scenario::Copies {
            vec![file_of(b"kept", MANAGED_DIR)]
        } else {
            vec![]
        };
        assert_eq!(plan.raised, raised, "{context}");
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
        let before_links = links(&state);
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
                    match (before.get(&path), before_links.get(&path)) {
                        // Byte for byte what the store had.
                        (Some(original), _) => {
                            assert_eq!(held.get(&path), Some(original), "{context}: {file}");
                        }
                        // The link itself, pointing where it did.
                        (None, Some(points_to)) => assert_eq!(
                            fs::read_link(quarantine.join(file)).ok().as_ref(),
                            Some(points_to),
                            "{context}: {file}"
                        ),
                        (None, None) => {
                            assert!(quarantine.join(file).is_dir(), "{context}: {file}");
                        }
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
        assert_untouched(&before, &state, scenario, &context);
        assert_eq!(FileStore::inspect_in(&state).unwrap(), [], "{context}");
        // A counter whose count is lost counts on from the clock, in a file
        // that took the place of whatever was there.
        if scenario.rebuilds_counter() {
            assert_eq!(served(&state).counter, Some(FROM_THE_CLOCK), "{context}");
            assert!(
                fs::symlink_metadata(state.join(SIGNATURE_COUNTER_FILE))
                    .unwrap()
                    .is_file(),
                "{context}"
            );
        }
        let store = FileStore::open(&state).unwrap();
        if scenario == Scenario::Copies {
            let kept = store.get(b"kept").unwrap().unwrap();
            assert_eq!(shown(kept.sign_count), FROM_THE_CLOCK, "{context}");
        }
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
        let left: BTreeSet<String> = if scenario == Scenario::MarkerOnly || scenario.counter_alone()
        {
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

/// The clock's seconds since 1970.
fn clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A counter whose count is lost is written at one more than the largest of
/// the clock's seconds since 1970, the newest change to the store, and every
/// counter repair read.  So it is above the clock; above the time the
/// counter's file, a record's in any directory of records, or the state
/// directory itself last changed, read before the quarantine changes the
/// directory, if the clock has gone back since; and above a record's counter
/// that is ahead of the clock.  A file's time at or past the largest count,
/// as on a stray file, is left out, so it does not stop the counter, which
/// reaches the largest count only from a time a second before it or a
/// counter one below it or at it.
#[test]
fn a_lost_count_is_written_above_the_clock_the_last_change_and_every_count() {
    let repaired = |setup: &dyn Fn(&Path)| {
        let scratch = TempDir::new();
        let state = scratch.path().join("state");
        Scenario::Counter.apply(&state);
        setup(&state);
        let plan = plan(&state);
        assert!(plan.counter);
        let before = clock();
        FileStore::repair_in(&state, &plan).unwrap();
        let count = u64::from(FileStore::unopened(&state).signature_counter().unwrap());
        (before, count, clock())
    };
    let (before, count, after) = repaired(&|_| {});
    assert!(
        (before + 1..=after + 1).contains(&count),
        "{before} < {count} <= {after} + 1"
    );

    // Ten days ahead of the clock, as when the clock went back ten days
    // since the counter's file, a record's, or the state directory, which
    // the quarantine is created in, was last written.  The records are in
    // each directory of records: `credential-set/records/`, and
    // `credential-set/`, which keeps the record of a passkey stored before
    // the upgrade, as a legacy store's `credentials/` keeps every record.
    let ahead = SystemTime::now() + Duration::from_secs(10 * 86_400);
    let ahead_seconds = ahead.duration_since(UNIX_EPOCH).unwrap().as_secs();
    for file in ["counter", "record", "upgraded record", "state directory"] {
        let (_, count, _) = repaired(&|state| {
            let store = FileStore::unopened(state);
            let opened = match file {
                "counter" => fs::File::options()
                    .write(true)
                    .open(state.join(SIGNATURE_COUNTER_FILE)),
                "record" => fs::File::options()
                    .write(true)
                    .open(record_file(&store, b"second")),
                "upgraded record" => {
                    let upgraded = record_file(&store, b"kept");
                    assert!(upgraded.starts_with(state.join(MANAGED_DIR)));
                    assert!(!upgraded.starts_with(state.join(MANAGED_DIR).join(RECORDS_DIR)));
                    fs::File::options().write(true).open(upgraded)
                }
                _ => fs::File::open(state),
            };
            opened.unwrap().set_modified(ahead).unwrap();
        });
        assert_eq!(count, ahead_seconds + 1, "{file}");
    }
    let scratch = TempDir::new();
    let state = scratch.path().join("legacy");
    let mut store = FileStore::open(&state).unwrap();
    store.put(&passkey(b"first", 1)).unwrap();
    store.set_signature_counter(500).unwrap();
    flip_last_byte(&state.join(SIGNATURE_COUNTER_FILE));
    let legacy = record_file(&store, b"first");
    assert!(legacy.starts_with(state.join(CREDENTIALS_DIR)));
    fs::File::options()
        .write(true)
        .open(legacy)
        .unwrap()
        .set_modified(ahead)
        .unwrap();
    FileStore::repair_in(&state, &plan(&state)).unwrap();
    assert_eq!(
        u64::from(FileStore::unopened(&state).signature_counter().unwrap()),
        ahead_seconds + 1,
        "legacy record"
    );

    // A time at or past the largest count, 2106-02-07T06:28:15Z or in 2200,
    // on the counter's own file or on a stray file in the state directory,
    // is left out.  A second earlier is the last time a count can be above:
    // the largest count.
    let stamped = |file: &str, seconds: u64| {
        repaired(&|state| {
            fs::File::options()
                .write(true)
                .create(true)
                .truncate(false)
                .open(state.join(file))
                .unwrap()
                .set_modified(UNIX_EPOCH + Duration::from_secs(seconds))
                .unwrap();
        })
    };
    for seconds in [u64::from(u32::MAX), 7_258_118_400] {
        for file in [SIGNATURE_COUNTER_FILE, "stray"] {
            let (before, count, after) = stamped(file, seconds);
            assert!(
                (before + 1..=after + 1).contains(&count),
                "{seconds} {file}: {before} < {count} <= {after} + 1"
            );
        }
    }
    let (_, count, _) = stamped("stray", u64::from(u32::MAX) - 1);
    assert_eq!(count, u64::from(u32::MAX));

    // A record counted past the clock, as one does that a repair raised
    // while the clock was ahead; and a record at the largest count.
    let past = u32::try_from(clock() + 1_000_000).unwrap();
    for (recorded, expected) in [(past, u64::from(past) + 1), (u32::MAX, u64::from(u32::MAX))] {
        let (_, count, _) = repaired(&|state| {
            let mut used = passkey(b"kept", 1);
            used.sign_count = recorded;
            FileStore::open(state).unwrap().put(&used).unwrap();
        });
        assert_eq!(count, expected, "{recorded}");
    }
}

/// Two authentic copies of one credential's record, one in each record
/// directory, as a writer outside this code could leave them: the passkey
/// `used`, migrated with the count 1000 to `credential-set/`, and a copy in
/// `credential-set/records/` with `other_count` and the creation order 7.
/// Returns the store and the records' file name.
fn copies(state: &Path, other_count: u32) -> (FileStore, String) {
    let mut store = FileStore::open(state).unwrap();
    let mut used = passkey(b"used", 1);
    used.sign_count = 1000;
    store.put(&used).unwrap();
    store
        .insert_or_replace_discoverable(&passkey(b"other", 2))
        .unwrap();
    used.sign_count = other_count;
    plant(&store, &used, 7, Location::Managed);
    let name = store
        .credential_keys()
        .unwrap()
        .unwrap()
        .file_name(b"used")
        .unwrap();
    (store, name)
}

/// The case the round-2 verifier's N5 left open, with the kept copy in
/// either record directory: the list names the copy with the higher
/// counter, which signs.  Then that copy and the list are damaged.  A
/// rebuild keeps the other copy, whose counter is lower than the count the
/// key returned, so repair raises it as it writes a lost shared counter
/// again, just above the clock, where it is, under its logical name, with
/// its creation order: the next sign-in returns a count above every count
/// returned before.  The copy is kept in the quarantine as it was.
#[test]
fn a_kept_copy_counts_on_above_what_its_damaged_copy_returned() {
    for kept_at in [Location::Legacy, Location::Managed] {
        let scratch = TempDir::new();
        let state = scratch.path().join("state");
        let higher = if kept_at == Location::Legacy {
            2000
        } else {
            500
        };
        let (store, name) = copies(&state, higher);
        let keys = store.credential_keys().unwrap().unwrap();
        if kept_at == Location::Legacy {
            // The list names the managed copy, which counted higher; cleanup
            // fails, so the migrated copy stays.
            let mut manifest = store.active_manifest(&keys).unwrap().unwrap();
            manifest.insert(name.clone(), Location::Managed);
            without_cleanup(|| store.publish_manifest(&keys, &manifest)).unwrap();
        }
        let damaged_at = if kept_at == Location::Legacy {
            Location::Managed
        } else {
            Location::Legacy
        };
        let kept_dir = store.record_dir(kept_at);
        let kept_before = store
            .read_credential_in(&keys, &name, &kept_dir, kept_at)
            .unwrap()
            .unwrap();
        let kept_contents = fs::read(kept_dir.join(&name)).unwrap();
        let mut app = CtapApp::with_file_store(
            FileStore::open(&state).unwrap(),
            AutoApprove,
            &INTERRUPT,
            [0; 16],
        );
        let returned = assertion_counter(&mut app, b"used");
        let context = format!("kept in {kept_at:?}");
        assert_eq!(
            returned,
            if kept_at == Location::Legacy {
                2001
            } else {
                1001
            },
            "{context}"
        );
        drop(app);

        flip_last_byte(&store.record_dir(damaged_at).join(&name));
        flip_last_byte(&state.join(MANAGED_DIR).join(ACTIVE_FILE));
        let plan = plan(&state);
        assert_eq!(plan.membership, Membership::Rebuilt, "{context}");
        let kept = store.relative(&kept_dir, &name);
        assert_eq!(plan.raised, std::slice::from_ref(&kept), "{context}");
        assert!(!plan.counter, "{context}");
        assert!(plan.moved.contains(&kept), "{context}: {:?}", plan.moved);
        let before = clock();
        let quarantine = FileStore::repair_in(&state, &plan)
            .unwrap()
            .quarantine
            .unwrap();
        let after = clock();
        assert_eq!(
            fs::read(quarantine.join(&kept)).unwrap(),
            kept_contents,
            "{context}"
        );
        let raised = store
            .read_credential_in(&keys, &name, &kept_dir, kept_at)
            .unwrap()
            .unwrap();
        // Just above the clock, so the site sees about when repair ran.
        assert!(
            (before + 1..=after + 1).contains(&u64::from(raised.sign_count)),
            "{context}: {before} < {} <= {after} + 1",
            raised.sign_count
        );
        assert_eq!(raised.created_at, kept_before.created_at, "{context}");
        let mut expected = kept_before.clone();
        expected.sign_count = raised.sign_count;
        assert_eq!(raised, expected, "{context}: only the count changes");
        assert_eq!(store.get(b"used").unwrap().unwrap(), raised, "{context}");
        assert_eq!(
            store.signature_counter().unwrap(),
            0,
            "{context}: the shared counter is left alone"
        );
        let mut app = CtapApp::with_file_store(store, AutoApprove, &INTERRUPT, [0; 16]);
        let next = assertion_counter(&mut app, b"used");
        assert!(next > returned, "{context}: {next} <= {returned}");
        assert_eq!(next, raised.sign_count + 1, "{context}");
    }
}

/// What `pqkey repair` advises for a record it cannot read: move it out of
/// the state directory and create an empty file of the same name in its place.
/// The empty file is damage repair handles as any other, with or without a
/// copy of the record in the other record directory.
///
/// * With an intact list, whose member is a directory, which fails reads
///   with EISDIR, as root too: planning refuses, naming it.  With the empty
///   file in its place, repair leaves the credential out of the list, and
///   moves the copy at the other location, which the list does not name,
///   into the quarantine too: the credential is off the key.
/// * In a rebuild, where the copy the list named and that signed last is
///   the one that cannot be read: with the empty file in its place, repair
///   keeps the other copy and raises its count above the one returned
///   before.  Moved out without an empty file, the copy would just be gone,
///   and the other kept without a raise.
#[test]
fn an_empty_file_in_an_unreadable_records_place_is_damage_repair_handles() {
    // An intact list, whose member cannot be read, and a copy elsewhere.
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let (store, name) = copies(&state, 2000);
    let member = store.record_dir(Location::Legacy).join(&name);
    fs::remove_file(&member).unwrap();
    fs::create_dir(&member).unwrap();
    let unchanged = entries(&state);
    let Err(StoreError::Io { path, .. }) = FileStore::plan_repair_in(&state) else {
        panic!("a record that cannot be read is planned");
    };
    assert_eq!(path, member);
    assert_eq!(entries(&state), unchanged, "planning changed it");
    fs::rename(&member, scratch.path().join("moved out")).unwrap();
    fs::write(&member, b"").unwrap();
    let kept = plan(&state);
    assert_eq!(kept.membership, Membership::Kept);
    assert_eq!(
        kept.damage,
        [Damage::corrupt(
            store.relative(&store.record_dir(Location::Legacy), &name),
            Corruption::Length
        )]
    );
    assert!(kept.raised.is_empty());
    for location in [Location::Legacy, Location::Managed] {
        let moved = store.relative(&store.record_dir(location), &name);
        assert!(kept.moved.contains(&moved), "{moved}: {:?}", kept.moved);
    }
    FileStore::repair_in(&state, &kept).unwrap();
    assert_eq!(store.get(b"used").unwrap(), None);
    assert_eq!(FileStore::inspect_in(&state).unwrap(), []);

    // A rebuild, where the copy that signed last cannot be read.
    for advice_followed in [true, false] {
        let scratch = TempDir::new();
        let state = scratch.path().join("state");
        let (store, name) = copies(&state, 2000);
        let keys = store.credential_keys().unwrap().unwrap();
        let mut manifest = store.active_manifest(&keys).unwrap().unwrap();
        manifest.insert(name.clone(), Location::Managed);
        without_cleanup(|| store.publish_manifest(&keys, &manifest)).unwrap();
        let mut app = CtapApp::with_file_store(
            FileStore::open(&state).unwrap(),
            AutoApprove,
            &INTERRUPT,
            [0; 16],
        );
        let returned = assertion_counter(&mut app, b"used");
        drop(app);
        let higher = store.record_dir(Location::Managed).join(&name);
        fs::rename(&higher, scratch.path().join("moved out")).unwrap();
        if advice_followed {
            fs::write(&higher, b"").unwrap();
        }
        flip_last_byte(&state.join(MANAGED_DIR).join(ACTIVE_FILE));
        let plan = plan(&state);
        assert_eq!(plan.membership, Membership::Rebuilt);
        let kept = store.relative(&store.record_dir(Location::Legacy), &name);
        if !advice_followed {
            assert_eq!(plan.raised, [] as [String; 0], "nothing tells it was there");
            continue;
        }
        assert_eq!(plan.raised, std::slice::from_ref(&kept));
        FileStore::repair_in(&state, &plan).unwrap();
        let mut app = CtapApp::with_file_store(store, AutoApprove, &INTERRUPT, [0; 16]);
        let next = assertion_counter(&mut app, b"used");
        assert!(next > returned, "{next} <= {returned}");
    }
}

/// A lost count alone, in a legacy store or one in the managed layout:
/// repair writes the counter again, and leaves every other file of the
/// store as it was, so a legacy store keeps its layout.
#[test]
fn a_lost_count_alone_leaves_the_credential_set_as_it_is() {
    for legacy in [true, false] {
        let scratch = TempDir::new();
        let state = scratch.path().join("state");
        let mut store = FileStore::open(&state).unwrap();
        store.put(&passkey(b"first", 1)).unwrap();
        if !legacy {
            store
                .insert_or_replace_discoverable(&passkey(b"second", 2))
                .unwrap();
        }
        store.put(&security_key(0x51)).unwrap();
        store.set_signature_counter(500).unwrap();
        flip_last_byte(&state.join(SIGNATURE_COUNTER_FILE));
        let before = files(&state);
        let plan = plan(&state);
        let context = if legacy { "legacy" } else { "managed" };
        assert_eq!(
            plan.damage,
            [Damage::corrupt(
                SIGNATURE_COUNTER_FILE,
                Corruption::Authentication
            )],
            "{context}"
        );
        assert_eq!(plan.membership, Membership::Intact, "{context}");
        assert!(plan.counter && !plan.marker, "{context}");
        assert_eq!(plan.raised, [] as [String; 0], "{context}");
        assert_eq!(plan.moved, [SIGNATURE_COUNTER_FILE], "{context}");
        let passkeys = if legacy { 1 } else { 2 };
        assert_eq!((plan.passkeys, plan.others), (passkeys, 1), "{context}");
        FileStore::repair_in(&state, &plan).unwrap();
        let after = files(&state);
        for (path, contents) in &before {
            if path != Path::new(SIGNATURE_COUNTER_FILE) {
                assert_eq!(
                    after.get(path),
                    Some(contents),
                    "{context}: {}",
                    path.display()
                );
            }
        }
        for path in after.keys().filter(|path| !before.contains_key(*path)) {
            assert!(
                path.starts_with(QUARANTINE),
                "{context}: {}",
                path.display()
            );
        }
        assert_eq!(state.join(CREDENTIALS_DIR).exists(), legacy, "{context}");
        assert_eq!(state.join(MANAGED_DIR).exists(), !legacy, "{context}");
        assert_eq!(FileStore::inspect_in(&state).unwrap(), [], "{context}");
        assert_eq!(
            FileStore::open(&state).unwrap().count().unwrap(),
            passkeys + 1
        );
    }
}

/// A directory in the counter's place, which fails reads with EISDIR, as
/// root too, is damage the inspection names, but repair cannot replace it
/// in one step, so planning refuses, naming it, and nothing changes.  Moved
/// out of the state directory, with an empty file created in its place, as
/// the refusal says, the counter is damage repair writes again above the clock,
/// moving the empty file into the quarantine.
#[test]
fn a_directory_in_the_counters_place_is_refused_until_an_empty_file_takes_it() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    managed(&state);
    let counter = state.join(SIGNATURE_COUNTER_FILE);
    fs::remove_file(&counter).unwrap();
    fs::create_dir(&counter).unwrap();
    fs::write(counter.join("left"), b"inside").unwrap();
    let found = FileStore::inspect_in(&state).unwrap();
    assert!(
        matches!(
            &found[..],
            [Damage { file, fault: Fault::Unreadable(_) }] if file == SIGNATURE_COUNTER_FILE
        ),
        "{found:?}"
    );
    let unchanged = entries(&state);
    let Err(StoreError::Io { path, source }) = FileStore::plan_repair_in(&state) else {
        panic!("a directory in the counter's place is planned");
    };
    assert_eq!(path, counter);
    assert_eq!(source.kind(), ErrorKind::IsADirectory);
    assert_eq!(
        source.to_string(),
        "is a directory, which repair cannot replace with a counter in one step"
    );
    assert_eq!(entries(&state), unchanged, "planning changed it");
    assert!(!state.join(QUARANTINE).exists());

    fs::rename(&counter, scratch.path().join("moved out")).unwrap();
    fs::write(&counter, b"").unwrap();
    let plan = plan(&state);
    assert_eq!(
        plan.damage,
        [Damage::corrupt(SIGNATURE_COUNTER_FILE, Corruption::Length)]
    );
    assert_eq!(plan.membership, Membership::Intact);
    assert!(plan.counter);
    assert_eq!(plan.moved, [SIGNATURE_COUNTER_FILE]);
    let before = clock();
    let quarantine = FileStore::repair_in(&state, &plan)
        .unwrap()
        .quarantine
        .unwrap();
    assert_eq!(
        fs::read(quarantine.join(SIGNATURE_COUNTER_FILE)).unwrap(),
        b""
    );
    let count = FileStore::unopened(&state).signature_counter().unwrap();
    assert!(u64::from(count) > before, "{count} <= {before}");
    assert_eq!(FileStore::inspect_in(&state).unwrap(), []);
}

/// Set the modification time of `path`, a file or a directory, to `seconds`
/// since 1970: the time a clock that read it then leaves on what it writes.
fn stamp(path: &Path, seconds: u64) {
    let file = if fs::symlink_metadata(path).unwrap().is_dir() {
        fs::File::open(path)
    } else {
        fs::File::options().write(true).open(path)
    };
    file.unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(seconds))
        .unwrap();
}

/// Set the modification time of the symbolic link `link` itself to
/// `seconds` since 1970, as [`stamp`] sets a file's.  The standard library
/// sets only the time of what a link points to, so `touch -h` copies it from
/// a file stamped with it.
fn stamp_link(link: &Path, seconds: u64) {
    let scratch = TempDir::new();
    let reference = scratch.path().join("reference");
    fs::write(&reference, b"").unwrap();
    stamp(&reference, seconds);
    let status = Command::new("touch")
        .arg("-h")
        .arg("-r")
        .arg(&reference)
        .arg(link)
        .status()
        .unwrap();
    assert!(status.success(), "touch -h: {status}");
    let metadata = fs::symlink_metadata(link).unwrap();
    assert!(metadata.file_type().is_symlink());
    assert_eq!(
        metadata.modified().unwrap(),
        UNIX_EPOCH + Duration::from_secs(seconds)
    );
}

/// An earlier repair of the store in `state` at `earlier`, by a clock that
/// was right then, left its quarantine with that time.
fn quarantined_at(state: &Path, earlier: u64) {
    let quarantine = state.join(QUARANTINE);
    fs::create_dir_all(quarantine.join("earlier")).unwrap();
    stamp(&quarantine.join("earlier"), earlier);
    stamp(&quarantine, earlier);
}

/// A managed store whose shared counter an earlier repair wrote again at
/// `earlier`, from a clock that was right then, and which counted on to
/// `earlier + 1000`, its last count at `earlier + 2000`, the clock still
/// right: the counter's file and the state directory have that time.
/// Returns the last count.
fn counted_on_after_a_repair(state: &Path, earlier: u64) -> u64 {
    let mut store = managed(state);
    let last = earlier + 1000;
    store
        .set_signature_counter(u32::try_from(last).unwrap())
        .unwrap();
    quarantined_at(state, earlier);
    stamp(&state.join(SIGNATURE_COUNTER_FILE), earlier + 2000);
    stamp(state, earlier + 2000);
    last
}

/// A directory takes the place of the counter of [`counted_on_after_a_repair`]
/// at `earlier + 2010`, the clock still right, and planning refuses it.  The
/// advice is followed: the directory is moved out of the state directory,
/// and an empty file is created in its place at `created`, or by this
/// machine's clock if `None`.  Returns the count repair then writes.
fn counter_advice_followed(state: &Path, earlier: u64, created: Option<u64>) -> u64 {
    let counter = state.join(SIGNATURE_COUNTER_FILE);
    fs::remove_file(&counter).unwrap();
    fs::create_dir(&counter).unwrap();
    stamp(&counter, earlier + 2010);
    stamp(state, earlier + 2010);
    assert!(FileStore::plan_repair_in(state).is_err());
    let outside = TempDir::new();
    fs::rename(&counter, outside.path().join("moved out")).unwrap();
    fs::write(&counter, b"").unwrap();
    if let Some(created) = created {
        stamp(&counter, created);
        stamp(state, created);
    }
    FileStore::repair_in(state, &plan(state)).unwrap();
    u64::from(FileStore::unopened(state).signature_counter().unwrap())
}

/// The passkey `used` of [`copies`], whose list names its copy in
/// `credential-set/records/`, while the upgrade's copy in `credential-set/`,
/// which cleanup could not remove, counts 1000.  An earlier repair at
/// `earlier`, from a clock that was right then, raised the listed copy's
/// count, which counted on to `earlier + 1000`, its last count at
/// `earlier + 2000`, the clock still right: that copy and its directory
/// have that time.  Returns the store, the records' name and the last count.
fn raised_and_counted_on(state: &Path, earlier: u64) -> (FileStore, String, u64) {
    let (store, name) = copies(state, u32::try_from(earlier + 999).unwrap());
    let keys = store.credential_keys().unwrap().unwrap();
    let mut manifest = store.active_manifest(&keys).unwrap().unwrap();
    manifest.insert(name.clone(), Location::Managed);
    without_cleanup(|| store.publish_manifest(&keys, &manifest)).unwrap();
    let mut app = CtapApp::with_file_store(
        FileStore::open(state).unwrap(),
        AutoApprove,
        &INTERRUPT,
        [0; 16],
    );
    let last = u64::from(assertion_counter(&mut app, b"used"));
    assert_eq!(last, earlier + 1000);
    drop(app);
    quarantined_at(state, earlier);
    let records = store.record_dir(Location::Managed);
    stamp(&records.join(&name), earlier + 2000);
    stamp(&records, earlier + 2000);
    (store, name, last)
}

/// The list of [`raised_and_counted_on`] is damaged, so repair rebuilds it,
/// and the copy it listed, which counted last, cannot be read.  The advice
/// for a record repair cannot read is followed: the copy is moved out of the
/// state directory, and an empty file of its name is created in its place at
/// `created`, or by this machine's clock if `None`.  Returns the count the
/// rebuild raises the other copy to.
fn record_advice_followed(
    state: &Path,
    store: &FileStore,
    name: &str,
    created: Option<u64>,
) -> u64 {
    let records = store.record_dir(Location::Managed);
    let unreadable = records.join(name);
    let outside = TempDir::new();
    fs::rename(&unreadable, outside.path().join("moved out")).unwrap();
    fs::write(&unreadable, b"").unwrap();
    if let Some(created) = created {
        stamp(&unreadable, created);
        stamp(&records, created);
    }
    flip_last_byte(&state.join(MANAGED_DIR).join(ACTIVE_FILE));
    let plan = plan(state);
    assert_eq!(plan.membership, Membership::Rebuilt);
    assert_eq!(
        plan.raised,
        [store.relative(&store.record_dir(Location::Legacy), name)]
    );
    FileStore::repair_in(state, &plan).unwrap();
    u64::from(store.get(b"used").unwrap().unwrap().sign_count)
}

/// What the third condition of the README's guarantee says of a clock that
/// is behind during a repair: it does no harm while the damaged file still
/// has the time a right clock gave it when the key last signed or later.
/// This machine's clock plays one that has gone back since: everything
/// before the repair is set in its future.  An earlier repair, with the
/// clock right, wrote a count from it, on which the key counted.
///
/// * The damaged file still has the time of the last count: the shared
///   counter, or the copy of a stored credential's record that counted last,
///   damaged where it is.  That time keeps the new count above the last.  So
///   does the time of a symbolic link that took the counter's place after
///   the last count, while the clock was right: repair reads the link's own
///   time, not its target's.
/// * The round-2 verifier's G1: the advice for a directory in the counter's
///   place, or for a record repair cannot read, followed while the clock is
///   behind.  The file that had the time of the last count is moved out, and
///   the empty file created in its place has the clock's time, behind it,
///   so the latest time left is the earlier repair's: the new count is below
///   the last.  So the advice asks for a right clock first.
/// * The round-3 verifier's V1b: the damaged file's time set back since, as
///   `touch -d` or a fault in the file system's metadata can leave it, while
///   its directory changed under the behind clock: the new count is below
///   the last too.
#[test]
fn a_behind_clock_does_no_harm_only_while_the_damaged_file_keeps_a_right_clocks_time() {
    let earlier = clock() + 100_000;
    let scratch = TempDir::new();

    let state = scratch.path().join("counter in place");
    let last = counted_on_after_a_repair(&state, earlier);
    let counter = state.join(SIGNATURE_COUNTER_FILE);
    // A flipped bit, which leaves the time of the last count.
    flip_last_byte(&counter);
    stamp(&counter, earlier + 2000);
    FileStore::repair_in(&state, &plan(&state)).unwrap();
    let count = u64::from(FileStore::unopened(&state).signature_counter().unwrap());
    assert_eq!(count, earlier + 2001);
    assert!(count > last);

    // A symbolic link took the counter's place at `earlier + 2010`, the clock
    // still right, pointing to a file outside the store that the behind clock
    // wrote; the state directory changed under the behind clock too.
    let state = scratch.path().join("counter link");
    let last = counted_on_after_a_repair(&state, earlier);
    let counter = state.join(SIGNATURE_COUNTER_FILE);
    let target = scratch.path().join("link target");
    fs::write(&target, b"not a counter").unwrap();
    fs::remove_file(&counter).unwrap();
    std::os::unix::fs::symlink(&target, &counter).unwrap();
    stamp_link(&counter, earlier + 2010);
    FileStore::repair_in(&state, &plan(&state)).unwrap();
    let count = u64::from(FileStore::unopened(&state).signature_counter().unwrap());
    assert_eq!(count, earlier + 2011);
    assert!(count > last);

    let state = scratch.path().join("counter by hand");
    let last = counted_on_after_a_repair(&state, earlier);
    let count = counter_advice_followed(&state, earlier, None);
    assert_eq!(count, earlier + 1);
    assert!(count < last, "{count} >= {last}");

    let state = scratch.path().join("record in place");
    let (store, name, last) = raised_and_counted_on(&state, earlier);
    let copy = store.record_dir(Location::Managed).join(&name);
    flip_last_byte(&copy);
    stamp(&copy, earlier + 2000);
    flip_last_byte(&state.join(MANAGED_DIR).join(ACTIVE_FILE));
    let planned = plan(&state);
    assert_eq!(
        planned.raised,
        [store.relative(&store.record_dir(Location::Legacy), &name)]
    );
    FileStore::repair_in(&state, &planned).unwrap();
    let count = u64::from(store.get(b"used").unwrap().unwrap().sign_count);
    assert_eq!(count, earlier + 2001);
    assert!(count > last);

    let state = scratch.path().join("record by hand");
    let (store, name, last) = raised_and_counted_on(&state, earlier);
    let count = record_advice_followed(&state, &store, &name, None);
    assert_eq!(count, earlier + 1);
    assert!(count < last, "{count} >= {last}");

    // Each damaged where it is, then its time set back, while its directory
    // changed under the behind clock, as the pid file `pqkey repair` removes,
    // or a registration, changes it.
    let state = scratch.path().join("counter set back");
    let last = counted_on_after_a_repair(&state, earlier);
    let counter = state.join(SIGNATURE_COUNTER_FILE);
    flip_last_byte(&counter);
    stamp(&counter, clock() - 1000);
    stamp(&state, clock());
    FileStore::repair_in(&state, &plan(&state)).unwrap();
    let count = u64::from(FileStore::unopened(&state).signature_counter().unwrap());
    assert_eq!(count, earlier + 1);
    assert!(count < last, "{count} >= {last}");

    let state = scratch.path().join("record set back");
    let (store, name, last) = raised_and_counted_on(&state, earlier);
    let records = store.record_dir(Location::Managed);
    let copy = records.join(&name);
    flip_last_byte(&copy);
    stamp(&copy, clock() - 1000);
    stamp(&records, clock());
    flip_last_byte(&state.join(MANAGED_DIR).join(ACTIVE_FILE));
    let planned = plan(&state);
    assert_eq!(
        planned.raised,
        [store.relative(&store.record_dir(Location::Legacy), &name)]
    );
    FileStore::repair_in(&state, &planned).unwrap();
    let count = u64::from(store.get(b"used").unwrap().unwrap().sign_count);
    assert_eq!(count, earlier + 1);
    assert!(count < last, "{count} >= {last}");
}

/// What the second condition of the README's guarantee excludes: a time
/// ahead of the real time that no clock of this computer left, read by a
/// repair, which starts above it.  Two seconds after that repair ended, the
/// key signs once, and another repair runs, under a right clock, every other
/// condition holding: one count in two whole seconds.  The round-3
/// verifier's V1a, at the store:
///
/// * A stray file dated ten days ahead is read again: the later repair
///   starts where the first did, so the next count repeats the one returned
///   in between.
/// * The damaged counter's own time, garbled ten days ahead, went with the
///   counter the first repair replaced: the later repair starts at the
///   clock, about ten days below the count returned in between.
#[test]
fn a_time_ahead_that_no_clock_left_lets_a_later_repair_repeat_or_go_back() {
    let ahead = clock() + 10 * 86_400;
    let scratch = TempDir::new();
    let mut repaired = Vec::new();
    for variant in ["stray file", "garbled counter"] {
        let state = scratch.path().join(variant);
        let store = managed(&state);
        let counter = state.join(SIGNATURE_COUNTER_FILE);
        flip_last_byte(&counter);
        if variant == "stray file" {
            fs::write(state.join("stray"), b"").unwrap();
            stamp(&state.join("stray"), ahead);
        } else {
            stamp(&counter, ahead);
        }
        FileStore::repair_in(&state, &plan(&state)).unwrap();
        let first = store.signature_counter().unwrap();
        assert_eq!(u64::from(first), ahead + 1, "{variant}");
        repaired.push((variant, state, store, first));
    }
    // Fewer counts than whole seconds since that repair ended, at the
    // sign-in and at the later repair.
    std::thread::sleep(Duration::from_secs(2));
    for (variant, state, mut store, first) in repaired {
        // A sealed sign-in counts on it, as the engine counts.
        let returned = first + 1;
        store.set_signature_counter(returned).unwrap();
        flip_last_byte(&state.join(SIGNATURE_COUNTER_FILE));
        FileStore::repair_in(&state, &plan(&state)).unwrap();
        let next = store.signature_counter().unwrap() + 1;
        if variant == "stray file" {
            assert_eq!(next, returned, "{variant}: the same count again");
        } else {
            assert!(u64::from(next) < ahead, "{variant}: {next}");
            assert!(next < returned, "{variant}: {next} >= {returned}");
        }
    }
}

/// Every counter planning read includes the shared counter when it is
/// intact: a raise planned while it is above the clock and the kept records
/// starts above it, and the shared counter is left as it is.
#[test]
fn a_raise_starts_above_an_intact_shared_counter() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let (mut store, name) = copies(&state, 2000);
    let shared = u32::try_from(clock() + 5_000_000).unwrap();
    store.set_signature_counter(shared).unwrap();
    flip_last_byte(&store.record_dir(Location::Managed).join(&name));
    flip_last_byte(&state.join(MANAGED_DIR).join(ACTIVE_FILE));
    let plan = plan(&state);
    assert!(!plan.counter);
    assert_eq!(
        plan.raised,
        [store.relative(&store.record_dir(Location::Legacy), &name)]
    );
    FileStore::repair_in(&state, &plan).unwrap();
    assert_eq!(store.get(b"used").unwrap().unwrap().sign_count, shared + 1);
    assert_eq!(store.signature_counter().unwrap(), shared);
}

/// What the advice for a directory in the counter's place, and for a record
/// repair cannot read, asks: a right clock when the empty file is created
/// and the repair runs.  Either keeps the new count above every count the
/// key returned, after an earlier repair that wrote a count from the clock.
///
/// * The empty file created while the clock is right, and the repair run
///   while it is behind, as this machine's clock plays it: the empty file
///   has the time it was created, after the last count.
/// * The empty file created while the clock is behind, before the earlier
///   repair, and the repair run while it is right, as this machine's clock
///   plays it: the new count is above the clock.
#[test]
fn the_advice_for_a_file_repair_cannot_read_keeps_counts_above_under_a_right_clock() {
    let scratch = TempDir::new();
    let earlier = clock() + 100_000;
    let state = scratch.path().join("counter, right when created");
    let last = counted_on_after_a_repair(&state, earlier);
    let count = counter_advice_followed(&state, earlier, Some(earlier + 2020));
    assert_eq!(count, earlier + 2021);
    assert!(count > last);
    let state = scratch.path().join("record, right when created");
    let (store, name, last) = raised_and_counted_on(&state, earlier);
    let count = record_advice_followed(&state, &store, &name, Some(earlier + 2020));
    assert_eq!(count, earlier + 2021);
    assert!(count > last);

    let earlier = clock() - 100_000;
    let state = scratch.path().join("counter, right during the repair");
    let last = counted_on_after_a_repair(&state, earlier);
    let before = clock();
    let count = counter_advice_followed(&state, earlier, Some(earlier - 50_000));
    assert!(count > before && before > last, "{count}, {before}, {last}");
    let state = scratch.path().join("record, right during the repair");
    let (store, name, last) = raised_and_counted_on(&state, earlier);
    let before = clock();
    let count = record_advice_followed(&state, &store, &name, Some(earlier - 50_000));
    assert!(count > before && before > last, "{count}, {before}, {last}");
}

/// What the README says of `damaged/`: it holds what repair took out of the
/// store, here an intact record the list no longer named, which reads with
/// the store's key until a reset replaces the key; and the store never
/// needs it, so deleting it changes nothing the key does.
#[test]
fn the_quarantine_reads_with_the_key_until_a_reset_and_the_store_never_needs_it() {
    for reset in [false, true] {
        let scratch = TempDir::new();
        let state = scratch.path().join("state");
        Scenario::Record.apply(&state);
        let plan = plan(&state);
        let quarantine = FileStore::repair_in(&state, &plan)
            .unwrap()
            .quarantine
            .unwrap();
        let mut store = FileStore::open(&state).unwrap();
        let keys = store.credential_keys().unwrap().unwrap();
        let name = keys.file_name(b"retired").unwrap();
        let held = quarantine.join(MANAGED_DIR).join(RECORDS_DIR);
        assert!(held.join(&name).is_file());
        let read = |store: &FileStore| {
            let keys = store.credential_keys().unwrap().unwrap();
            store.read_credential_in(&keys, &name, &held, Location::Managed)
        };
        if reset {
            store.clear().unwrap();
            assert!(held.join(&name).is_file(), "a reset leaves it");
            assert!(matches!(
                read(&store),
                Err(StoreError::Corrupt {
                    reason: Corruption::Authentication,
                    ..
                })
            ));
            continue;
        }
        assert_eq!(
            read(&store).unwrap().unwrap().credential_id,
            b"retired".to_vec()
        );
        let listed = |store: &FileStore| {
            let mut listed: Vec<_> = store
                .list()
                .unwrap()
                .into_iter()
                .map(|record| (record.credential_id.clone(), record.sign_count))
                .collect();
            listed.sort();
            listed
        };
        let before = listed(&store);
        fs::remove_dir_all(state.join(QUARANTINE)).unwrap();
        assert_eq!(listed(&store), before);
        assert_eq!(FileStore::inspect_in(&state).unwrap(), []);
        assert_eq!(FileStore::plan_repair_in(&state).unwrap(), None);
        let mut app = CtapApp::with_file_store(store, AutoApprove, &INTERRUPT, [0; 16]);
        assert_eq!(sign_in(&mut app, b"kept"), CTAP2_OK);
        assert_eq!(register(&mut app), CTAP2_OK);
    }
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
