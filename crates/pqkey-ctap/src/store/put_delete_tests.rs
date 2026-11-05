//! Real filesystem failures and process exits in managed `put` and `delete`.
//!
//! The store's commit rules give each of these operations one commit point:
//!
//! * Putting a new credential and deleting one change membership, so they
//!   commit when the manifest is published. An error before that leaves the
//!   preceding set, and from publication on they return success.
//! * Putting a credential the store holds replaces only its record and keeps
//!   the per-record semantics: every error fails it, but an error after the
//!   record's rename leaves the new record in place.
//!
//! Each sweep records the checkpoints of one operation on a migrated store,
//! then runs it again on a newly set up store for every checkpoint,
//! injecting an error there or exiting a child process there. Afterwards the
//! operation took effect completely if that checkpoint is its commit point or
//! a later one, and not at all if it is an earlier one. The store is also
//! consistent and usable: every member of the manifest has a readable record,
//! list, count and get agree on exactly the expected records, the untouched
//! ones unchanged, and a following registration and delete succeed and leave
//! no ciphertext outside the membership.
//!
//! The tests after the sweeps check what the cleanup after a membership
//! change removes besides retired records: a copy of a member at the
//! location its manifest entry does not name, but never a member whose only
//! file is there. Only a regular file at the member's own location makes
//! the other one a copy, and a failed lookup there keeps both.

use std::cell::{Cell, RefCell};
use std::process::{Command, Stdio};
use std::rc::Rc;

use super::*;
use crate::CoseAlg;
use crate::credential_id::{DISCOVERABLE_MARKER, NON_DISCOVERABLE_MARKER};
use crate::store::{PrivateKeyMaterial, test_support::TempDir};

/// A credential whose ID is `marker` and 32 bytes of `fill`.
fn credential(marker: u8, fill: u8) -> CredentialRecord {
    let mut credential_id = vec![fill; 33];
    credential_id[0] = marker;
    CredentialRecord {
        credential_id,
        rp_id: "example.com".into(),
        user_id: vec![fill],
        user_name: None,
        user_display_name: None,
        alg: CoseAlg::ES256,
        private_key: PrivateKeyMaterial::P256Scalar { scalar: [fill; 32] },
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

/// A payment-enabled Brainpool credential, which only a stored record holds.
fn brainpool(fill: u8) -> CredentialRecord {
    let mut record = credential(NON_DISCOVERABLE_MARKER, fill);
    record.alg = CoseAlg::ESB256;
    record.private_key = PrivateKeyMaterial::Seed { seed: [fill; 32] };
    record.third_party_payment = true;
    record
}

/// Put in the legacy layout and moved to `credential-set/` by the migration.
fn migrated_discoverable() -> CredentialRecord {
    credential(DISCOVERABLE_MARKER, 0x22)
}

/// The registration that migrated the store, in `credential-set/records/`.
fn registered() -> CredentialRecord {
    credential(DISCOVERABLE_MARKER, 0x33)
}

/// Put after the migration, in `credential-set/records/`.
fn stored() -> CredentialRecord {
    brainpool(0x44)
}

/// The registration that follows each failure.
fn following() -> CredentialRecord {
    credential(DISCOVERABLE_MARKER, 0x66)
}

/// A store migrated by a registration: `credential-set/` holds the two
/// records put in the legacy layout, `credential-set/records/` the
/// registration and a stored credential put after it.
fn setup(path: &Path) -> FileStore {
    let mut store = FileStore::open(path).unwrap();
    store
        .put(&credential(NON_DISCOVERABLE_MARKER, 0x11))
        .unwrap();
    store.put(&migrated_discoverable()).unwrap();
    store.insert_or_replace_discoverable(&registered()).unwrap();
    store.put(&stored()).unwrap();
    store
}

/// A managed `put` or `delete` on the store [`setup`] makes.
#[derive(Clone, Copy, Debug)]
enum Operation {
    /// Puts a new stored credential, as RSA, Brainpool and payment-enabled
    /// registrations do.
    Insert,
    /// Puts the stored credential in `credential-set/records/` with its
    /// counter advanced, as a signature does.
    UpdateManaged,
    /// Puts a migrated credential with new user information, as credential
    /// management does.
    UpdateMigrated,
    /// Deletes the registration in `credential-set/records/`.
    DeleteManaged,
    /// Deletes a migrated credential.
    DeleteMigrated,
}

const PUTS: [Operation; 3] = [
    Operation::Insert,
    Operation::UpdateManaged,
    Operation::UpdateMigrated,
];
const DELETES: [Operation; 2] = [Operation::DeleteManaged, Operation::DeleteMigrated];

impl Operation {
    /// The credential it inserts, updates or deletes.
    fn target(self) -> CredentialRecord {
        match self {
            Self::Insert => brainpool(0x55),
            Self::UpdateManaged => stored(),
            Self::UpdateMigrated | Self::DeleteMigrated => migrated_discoverable(),
            Self::DeleteManaged => registered(),
        }
    }

    fn id(self) -> Vec<u8> {
        self.target().credential_id.clone()
    }

    /// The record it puts, or `None` for a deletion.
    fn record(self) -> Option<CredentialRecord> {
        let mut record = self.target();
        match self {
            Self::Insert => {}
            Self::UpdateManaged => record.sign_count += 1,
            Self::UpdateMigrated => record.user_name = Some("renamed".into()),
            Self::DeleteManaged | Self::DeleteMigrated => return None,
        }
        Some(record)
    }

    fn run(self, store: &mut FileStore) -> Result<(), StoreError> {
        match self.record() {
            Some(record) => store.put(&record),
            None => store
                .delete(&self.id())
                .map(|deleted| assert!(deleted, "{self:?} found nothing to delete")),
        }
    }

    /// Whether it replaces a record the store holds, leaving membership as
    /// it was.
    fn updates(self) -> bool {
        matches!(self, Self::UpdateManaged | Self::UpdateMigrated)
    }

    /// The first checkpoint by which it has taken effect.
    fn commit_point(self) -> &'static str {
        if self.updates() {
            "renamed"
        } else {
            "published"
        }
    }

    /// The records once it took effect on `before`.
    fn applied(self, before: &[CredentialRecord]) -> Vec<CredentialRecord> {
        let id = self.id();
        let mut after: Vec<_> = before
            .iter()
            .filter(|record| record.credential_id != id)
            .cloned()
            .collect();
        if let Some(mut record) = self.record() {
            // An insert is the newest; an update keeps its creation order.
            record.created_at = before
                .iter()
                .find(|old| old.credential_id == id)
                .map_or_else(|| next_created_at(before), |old| old.created_at);
            after.push(record);
        }
        after
    }
}

/// The checkpoints of `operation` succeeding on a fresh store, and the index
/// of its commit point among them.
fn trace(operation: Operation) -> (Vec<String>, usize) {
    let scratch = TempDir::new();
    let mut store = setup(&scratch.path().join("state"));
    let members = members(&store, "setup");
    for location in [Location::Legacy, Location::Managed] {
        assert_eq!(
            members.values().filter(|&&at| at == location).count(),
            2,
            "the sweep covers records at {location:?}"
        );
    }
    let events = Rc::new(RefCell::new(Vec::new()));
    let recorded = Rc::clone(&events);
    fsio::with_hook(
        Box::new(move |event, _| {
            recorded.borrow_mut().push(event.to_owned());
            Ok(())
        }),
        || operation.run(&mut store),
    )
    .unwrap();
    let events = events.take();
    if !operation.updates() {
        assert!(
            events.iter().any(|event| event == "cleanup"),
            "{operation:?}: the sweep covers cleanup"
        );
    }
    let commit = events
        .iter()
        .position(|event| event == operation.commit_point())
        .unwrap();
    (events, commit)
}

fn sweep_errors(operations: &[Operation]) {
    for &operation in operations {
        let (events, commit) = trace(operation);
        for (boundary, event) in events.iter().enumerate() {
            let scratch = TempDir::new();
            let path = scratch.path().join("state");
            let mut store = setup(&path);
            let before = store.list().unwrap();
            let mut index = 0;
            let result = fsio::with_hook(
                Box::new(move |_, path| {
                    let current = index;
                    index += 1;
                    if current == boundary {
                        Err(fsio::io_error(
                            path,
                            std::io::Error::other("injected boundary failure"),
                        ))
                    } else {
                        Ok(())
                    }
                }),
                || operation.run(&mut store),
            );
            let committed = boundary >= commit;
            let context = format!("{operation:?}, boundary {boundary}: {event}");
            assert_eq!(
                result.is_ok(),
                committed && !operation.updates(),
                "{context}: {result:?}"
            );
            assert_recovers(&path, operation, committed, &before, &context);
        }
    }
}

#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("PQKEY_PUT_DELETE_CHILD") else {
        return;
    };
    let name = std::env::var("PQKEY_PUT_DELETE_OPERATION").unwrap();
    let operation = PUTS
        .into_iter()
        .chain(DELETES)
        .find(|operation| format!("{operation:?}") == name)
        .unwrap();
    let boundary: usize = std::env::var("PQKEY_PUT_DELETE_BOUNDARY")
        .unwrap()
        .parse()
        .unwrap();
    let mut store = FileStore::open(PathBuf::from(path)).unwrap();
    let mut index = 0;
    let result = fsio::with_hook(
        Box::new(move |_, _| {
            let current = index;
            index += 1;
            if current == boundary {
                std::process::exit(83);
            }
            Ok(())
        }),
        || operation.run(&mut store),
    );
    panic!("crash boundary not reached: {operation:?} {boundary}, {result:?}");
}

fn sweep_exits(operations: &[Operation]) {
    for &operation in operations {
        let (events, commit) = trace(operation);
        for (boundary, event) in events.iter().enumerate() {
            let scratch = TempDir::new();
            let path = scratch.path().join("state");
            let before = setup(&path).list().unwrap();
            let context = format!("{operation:?}, boundary {boundary}: {event}");
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::file::put_delete_tests::crash_child",
                    "--nocapture",
                ])
                .env("PQKEY_PUT_DELETE_CHILD", &path)
                .env("PQKEY_PUT_DELETE_OPERATION", format!("{operation:?}"))
                .env("PQKEY_PUT_DELETE_BOUNDARY", boundary.to_string())
                .stdout(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(83), "{context}");
            assert_recovers(&path, operation, boundary >= commit, &before, &context);
        }
    }
}

/// After a failure at `context`, the store at `path` holds `before`, with
/// the operation applied if it `committed`, and is usable.
fn assert_recovers(
    path: &Path,
    operation: Operation,
    committed: bool,
    before: &[CredentialRecord],
    context: &str,
) {
    let mut store = FileStore::open(path).unwrap();
    let expected = if committed {
        operation.applied(before)
    } else {
        before.to_vec()
    };
    assert_holds(&store, &expected, context);
    let id = operation.id();
    let held = expected.iter().any(|record| record.credential_id == id);
    if !held {
        assert_eq!(ok(store.get(&id), context), None, "{context}");
    }
    assert_eq!(
        ok(store.insert_or_replace_discoverable(&following()), context),
        CredentialCommit {
            durability: CommitDurability::Flushed,
            cleanup_pending: false,
        },
        "{context}"
    );
    assert_eq!(ok(store.delete(&id), context), held, "{context}");
    let mut registration = following();
    registration.created_at = next_created_at(&expected);
    let mut remaining: Vec<_> = expected
        .into_iter()
        .filter(|record| record.credential_id != id)
        .collect();
    remaining.push(registration);
    assert_holds(&store, &remaining, context);
    // Their cleanup reclaimed what the failure left outside membership.
    assert_eq!(ciphertext(&store), members(&store, context), "{context}");
}

/// The store holds exactly `expected`: every member of its manifest has a
/// readable record, and list, count and get agree on them.
fn assert_holds(store: &FileStore, expected: &[CredentialRecord], context: &str) {
    let keys = store.credential_keys().unwrap().unwrap();
    let members = members(store, context);
    for (name, &location) in &members {
        let record = store.read_credential_in(&keys, name, &store.record_dir(location), location);
        assert!(
            matches!(record, Ok(Some(_))),
            "{context}: member {name} reads as {record:?}"
        );
    }
    let mut expected = expected.to_vec();
    sort_newest_first(&mut expected);
    assert_eq!(ok(store.list(), context), expected, "{context}");
    assert_eq!(ok(store.count(), context), expected.len(), "{context}");
    assert_eq!(members.len(), expected.len(), "{context}");
    for record in &expected {
        assert_eq!(
            ok(store.get(&record.credential_id), context).as_ref(),
            Some(record),
            "{context}"
        );
    }
}

fn members(store: &FileStore, context: &str) -> Manifest {
    let keys = store.credential_keys().unwrap().unwrap();
    ok(store.active_manifest(&keys), context).expect("the store is migrated")
}

/// The credential-named files in the managed namespace, by location.
fn ciphertext(store: &FileStore) -> Manifest {
    let mut files = Manifest::new();
    for location in [Location::Legacy, Location::Managed] {
        for entry in fs::read_dir(store.record_dir(location)).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            if is_credential_file_name(&name) {
                assert_eq!(files.insert(name, location), None);
            }
        }
    }
    files
}

fn ok<T>(result: Result<T, StoreError>, context: &str) -> T {
    result.unwrap_or_else(|err| panic!("{context}: {err}"))
}

#[test]
fn every_checkpoint_error_in_managed_put_commits_completely_or_not_at_all() {
    sweep_errors(&PUTS);
}

#[test]
fn process_exit_at_every_checkpoint_of_managed_put_leaves_a_usable_store() {
    sweep_exits(&PUTS);
}

#[test]
fn every_checkpoint_error_in_managed_delete_commits_completely_or_not_at_all() {
    sweep_errors(&DELETES);
}

#[test]
fn process_exit_at_every_checkpoint_of_managed_delete_leaves_a_usable_store() {
    sweep_exits(&DELETES);
}

/// The record location a manifest entry does not name.
fn other(location: Location) -> Location {
    match location {
        Location::Legacy => Location::Managed,
        Location::Managed => Location::Legacy,
    }
}

const FLUSHED: CredentialCommit = CredentialCommit {
    durability: CommitDurability::Flushed,
    cleanup_pending: false,
};

/// A manifest that places every member at the location without its file, as
/// a decoder with the two location bytes swapped reads an upgraded store,
/// hides the records but deletes none of them. Neither its own publication
/// nor the insert and deletion committed after it remove a record file,
/// except the deleted credential's, and the true manifest restores them all.
#[test]
fn a_manifest_misplacing_every_member_hides_its_records_but_deletes_none() {
    let scratch = TempDir::new();
    let mut store = setup(&scratch.path().join("state"));
    let keys = store.credential_keys().unwrap().unwrap();
    let before = store.list().unwrap();
    let manifest = members(&store, "setup");
    let files = ciphertext(&store);
    assert_eq!(files, manifest);
    let misplaced: Manifest = manifest
        .iter()
        .map(|(name, &location)| (name.clone(), other(location)))
        .collect();
    assert_eq!(store.publish_manifest(&keys, &misplaced).unwrap(), FLUSHED);
    assert_eq!(store.list().unwrap(), []);
    // The membership changes such a store still commits: a stored
    // registration (RSA, Brainpool or payment) and a deletion.
    let inserted = Operation::Insert.target();
    store.put(&inserted).unwrap();
    assert!(store.delete(&inserted.credential_id).unwrap());
    assert_eq!(members(&store, "misplaced"), misplaced);
    assert_eq!(ciphertext(&store), files, "every record file is kept");
    assert_eq!(store.publish_manifest(&keys, &manifest).unwrap(), FLUSHED);
    assert_holds(&store, &before, "restored");
    assert_eq!(ciphertext(&store), manifest);
}

/// A copy of each member at the location its manifest entry does not name,
/// as moving a record between locations would leave the old one, is
/// reclaimed by the next membership change, here a replacement, together
/// with the replaced credential's file. Every member keeps its own file.
#[test]
fn a_members_copy_at_the_other_location_is_reclaimed() {
    let scratch = TempDir::new();
    let mut store = setup(&scratch.path().join("state"));
    let before = store.list().unwrap();
    for (name, &location) in &members(&store, "setup") {
        fs::copy(
            store.record_dir(location).join(name),
            store.record_dir(other(location)).join(name),
        )
        .unwrap();
    }
    let mut successor = following();
    successor.user_id.clone_from(&registered().user_id);
    assert_eq!(
        store.insert_or_replace_discoverable(&successor).unwrap(),
        FLUSHED
    );
    successor.created_at = next_created_at(&before);
    let mut expected: Vec<_> = before
        .into_iter()
        .filter(|record| record.credential_id != registered().credential_id)
        .collect();
    expected.push(successor);
    assert_holds(&store, &expected, "replaced");
    assert_eq!(ciphertext(&store), members(&store, "replaced"));
}

/// If looking for a member's file at its own location fails, its copy at
/// the other location is kept and cleanup stays pending. The next
/// membership change reclaims it.
#[test]
fn a_failed_lookup_keeps_the_copy_and_leaves_cleanup_pending() {
    let scratch = TempDir::new();
    let mut store = setup(&scratch.path().join("state"));
    let before = store.list().unwrap();
    let keys = store.credential_keys().unwrap().unwrap();
    let name = keys.file_name(&stored().credential_id).unwrap();
    let own = store.record_dir(Location::Managed).join(&name);
    let copy = store.record_dir(Location::Legacy).join(&name);
    fs::copy(&own, &copy).unwrap();
    let commit = fsio::with_hook(
        Box::new(move |event, path| {
            if event == "lookup" {
                assert_eq!(path, own);
                Err(fsio::io_error(
                    path,
                    std::io::Error::other("injected lookup failure"),
                ))
            } else {
                Ok(())
            }
        }),
        || store.insert_or_replace_discoverable(&following()),
    );
    assert_eq!(
        commit.unwrap(),
        CredentialCommit {
            durability: CommitDurability::Flushed,
            cleanup_pending: true,
        }
    );
    assert!(copy.is_file());
    assert!(store.delete(&following().credential_id).unwrap());
    assert!(!copy.exists());
    assert_holds(&store, &before, "retried");
    assert_eq!(ciphertext(&store), members(&store, "retried"));
}

/// Move the stored credential's only file from `records/`, where its
/// manifest entry places it, up to `credential-set/`. Returns where the
/// manifest looks for it and where it now is.
fn misplace_stored(store: &FileStore) -> (PathBuf, PathBuf) {
    let keys = store.credential_keys().unwrap().unwrap();
    let name = keys.file_name(&stored().credential_id).unwrap();
    let own = store.record_dir(Location::Managed).join(&name);
    let misplaced = store.record_dir(Location::Legacy).join(&name);
    fsio::rename(&own, &misplaced, "rename", "renamed")
        .unwrap()
        .unwrap();
    (own, misplaced)
}

/// A symbolic link at the member's own location is not a regular file
/// there, even one to the member's only file elsewhere: that file is kept,
/// cleanup completes, and the member reads through the link.
#[test]
fn a_symbolic_link_at_the_members_location_is_not_its_file() {
    let scratch = TempDir::new();
    let store = setup(&scratch.path().join("state"));
    let keys = store.credential_keys().unwrap().unwrap();
    let before = store.list().unwrap();
    let manifest = members(&store, "setup");
    let (own, misplaced) = misplace_stored(&store);
    let sealed = fs::read(&misplaced).unwrap();
    std::os::unix::fs::symlink(&misplaced, &own).unwrap();
    assert_eq!(store.publish_manifest(&keys, &manifest).unwrap(), FLUSHED);
    assert!(misplaced.is_file(), "the member's only file is kept");
    assert_eq!(fs::read(&misplaced).unwrap(), sealed);
    assert_holds(&store, &before, "linked");
}

/// Nor is a directory of the member's name: its only file is kept, and
/// cleanup completes.
#[test]
fn a_directory_at_the_members_location_is_not_its_file() {
    let scratch = TempDir::new();
    let store = setup(&scratch.path().join("state"));
    let keys = store.credential_keys().unwrap().unwrap();
    let before = store.list().unwrap();
    let manifest = members(&store, "setup");
    let (own, misplaced) = misplace_stored(&store);
    let sealed = fs::read(&misplaced).unwrap();
    fs::create_dir(&own).unwrap();
    assert_eq!(store.publish_manifest(&keys, &manifest).unwrap(), FLUSHED);
    assert!(misplaced.is_file(), "the member's only file is kept");
    assert_eq!(fs::read(&misplaced).unwrap(), sealed);
    fsio::remove_dir(&own).unwrap();
    fsio::rename(&misplaced, &own, "rename", "renamed")
        .unwrap()
        .unwrap();
    assert_holds(&store, &before, "moved back");
}

/// A real lookup error at the member's own location, ENOTDIR from a
/// `records/` that is briefly a regular file, keeps the member's only file
/// at the other location and leaves cleanup pending. The hook puts the
/// directory back when cleanup reaches `records/` itself, so the lookup is
/// the only thing that fails. The next commit keeps the file again.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the hook moves records/ back with std::fs: the store's wrappers would re-enter it"
)]
fn a_real_lookup_error_keeps_a_misplaced_member_and_leaves_cleanup_pending() {
    let scratch = TempDir::new();
    let store = setup(&scratch.path().join("state"));
    let keys = store.credential_keys().unwrap().unwrap();
    let before = store.list().unwrap();
    let manifest = members(&store, "setup");
    let (own, misplaced) = misplace_stored(&store);
    let records = store.record_dir(Location::Managed);
    let aside = scratch.path().join("records");
    fs::rename(&records, &aside).unwrap();
    fs::write(&records, b"not a directory").unwrap();
    let lookups = Rc::new(Cell::new(0));
    let counted = Rc::clone(&lookups);
    let dir = records.clone();
    let commit = fsio::with_hook(
        Box::new(move |event, path| {
            if event == "lookup" {
                counted.set(counted.get() + 1);
            }
            if event == "cleanup" && path == dir {
                fs::remove_file(&dir).unwrap();
                fs::rename(&aside, &dir).unwrap();
            }
            Ok(())
        }),
        || store.publish_manifest(&keys, &manifest),
    );
    assert_eq!(lookups.get(), 1);
    assert!(misplaced.is_file(), "the member's only file is kept");
    assert!(records.is_dir());
    assert_eq!(
        commit.unwrap(),
        CredentialCommit {
            durability: CommitDurability::Flushed,
            cleanup_pending: true,
        }
    );
    assert_eq!(store.publish_manifest(&keys, &manifest).unwrap(), FLUSHED);
    assert!(misplaced.is_file());
    fsio::rename(&misplaced, &own, "rename", "renamed")
        .unwrap()
        .unwrap();
    assert_holds(&store, &before, "moved back");
    assert_eq!(ciphertext(&store), manifest);
}
