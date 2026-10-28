//! The order of the store's flushes against its renames, links and removals.
//!
//! The crash tests beside this module inject errors and process exits at the
//! checkpoints. Those lose nothing that was written but not yet flushed, so a
//! missing or late flush passes them; only a power failure would show it.
//! This test checks the order instead, on the checkpoint trace of every
//! operation that persists something. The trace is complete because each
//! flush, rename, link and removal emits its own checkpoints from its `fsio`
//! wrapper, and the crate's `clippy.toml` refuses those calls anywhere else.
//!
//! The rules name events and the files and directories they touch, not whole
//! sequences, so unrelated events may move:
//!
//! 1. Only a file the operation wrote and then flushed is renamed or linked
//!    into place, so no name points at contents a power failure takes back.
//! 2. Membership is published only after the directory of everything put in
//!    place before it was flushed, such as the new record and the format
//!    marker, and no record is put in place after it, so a durable manifest
//!    never names a record that is not.
//! 3. A staged namespace is renamed into place only after it was flushed
//!    following the last change to its entries.
//! 4. No cleanup starts and nothing is removed until the directory of
//!    everything put in place before was flushed, so a power failure cannot
//!    bring back a manifest that names a removed record, or the old key after
//!    a reset removed its counter.
//! 5. Every change is flushed before the operation returns.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::os::unix::fs::MetadataExt;
use std::rc::Rc;

use super::*;
use crate::CoseAlg;
use crate::store::{PrivateKeyMaterial, test_support::TempDir};

const FLUSHED_BEFORE_PLACED: &str =
    "rule 1 (a file is written and flushed before it is put in place)";
const MEMBERSHIP_LAST: &str = "rule 2 (membership is published after what it names)";
const NAMESPACE_FLUSHED: &str = "rule 3 (a staged namespace is flushed before it is renamed)";
const DURABLE_BEFORE_REMOVAL: &str =
    "rule 4 (nothing is removed before earlier changes are durable)";
const DURABLE_BEFORE_RETURN: &str = "rule 5 (every change is flushed before the operation returns)";
const RULES: [&str; 5] = [
    FLUSHED_BEFORE_PLACED,
    MEMBERSHIP_LAST,
    NAMESPACE_FLUSHED,
    DURABLE_BEFORE_REMOVAL,
    DURABLE_BEFORE_RETURN,
];

type Setup = fn(&Path) -> FileStore;
type Operation = fn(&mut FileStore);

#[test]
fn every_persisting_operation_flushes_before_it_publishes_removes_or_returns() {
    let operations: [(&str, Setup, Operation); 18] = [
        ("legacy put of a new record", legacy, |store| {
            store.put(&credential(b"new", 4)).unwrap();
        }),
        ("legacy put of an existing record", legacy, |store| {
            store.put(&used(b"kept", 1)).unwrap();
        }),
        ("legacy delete", legacy, |store| {
            assert!(store.delete(b"kept").unwrap());
        }),
        ("migration replacing a legacy record", legacy, |store| {
            committed(store.insert_or_replace_discoverable(&credential(b"successor", 2)));
        }),
        ("managed put of a new record", managed, |store| {
            store.put(&credential(b"new", 4)).unwrap();
        }),
        ("managed put of a managed record", managed, |store| {
            store.put(&used(b"managed", 3)).unwrap();
        }),
        ("managed put of a migrated record", managed, |store| {
            store.put(&used(b"kept", 1)).unwrap();
        }),
        ("replacement of a managed record", managed, |store| {
            committed(store.insert_or_replace_discoverable(&credential(b"successor", 3)));
        }),
        ("managed delete of a managed record", managed, |store| {
            assert!(store.delete(b"managed").unwrap());
        }),
        ("managed delete of a migrated record", managed, |store| {
            assert!(store.delete(b"kept").unwrap());
        }),
        (
            "reset of a legacy store",
            |path| provisioned(legacy(path)),
            reset,
        ),
        (
            "reset of a managed store",
            |path| provisioned(managed(path)),
            reset,
        ),
        ("reset after an interrupted migration", interrupted, reset),
        ("PIN state publication", fresh, |store| {
            assert_eq!(
                store.set_pin_state(&pin()).unwrap(),
                CommitDurability::Flushed
            );
        }),
        ("signature counter update", fresh, |store| {
            store.set_signature_counter(7).unwrap();
        }),
        ("large-blob array write", fresh, |store| {
            store
                .set_large_blob_array(&INITIAL_LARGE_BLOB_ARRAY)
                .unwrap();
        }),
        ("attestation write", fresh, |store| {
            store.set_attestation(&attestation()).unwrap();
        }),
        // Sealing writes the default PIN state if there is none.
        ("sealing the first credential ID", fresh, |store| {
            store.seal_credential_id(&[7; 66], RP.as_bytes()).unwrap();
        }),
    ];
    let mut exercised = BTreeSet::new();
    let mut violations = Vec::new();
    let mut audit = |operation: &str, scratch: &TempDir, events: Vec<Event>| {
        violations.extend(
            check(scratch.path(), &events, &mut exercised)
                .into_iter()
                .map(|violation| format!("{operation}: {violation}")),
        );
    };
    let scratch = TempDir::new();
    let events = trace(|| drop(FileStore::open(scratch.path().join("state")).unwrap()));
    audit("opening a new store", &scratch, events);
    for (operation, setup, run) in operations {
        let scratch = TempDir::new();
        let mut store = setup(&scratch.path().join("state"));
        let events = trace(|| run(&mut store));
        audit(operation, &scratch, events);
    }
    assert!(
        violations.is_empty(),
        "durability order violated:\n{}",
        violations.join("\n")
    );
    assert_eq!(exercised, BTreeSet::from(RULES), "every rule has a case");
}

/// A checkpoint of the traced operation.
#[derive(Debug)]
struct Event {
    name: String,
    path: PathBuf,
    /// The inode of the directory a flush flushed, or of the one in which a
    /// change put or removed an entry. Directories are compared by inode,
    /// because the staged namespace keeps its entries but changes its name.
    dir: Option<u64>,
    /// At the end of a rename or link, the entry that now has `path`'s name.
    moved: Option<Moved>,
}

#[derive(Debug)]
struct Moved {
    path: PathBuf,
    /// Its inode, if it is a directory.
    dir: Option<u64>,
}

impl Event {
    fn is(&self, name: &str, path: &Path) -> bool {
        self.name == name && self.path == path
    }

    /// Whether this completes putting an entry in place at `path`: a rename,
    /// a publication or a link.
    fn placed(&self) -> bool {
        matches!(self.name.as_str(), "renamed" | "published" | "linked")
    }

    /// Whether this put an entry in place, or removed one that is not a
    /// temporary file.
    fn changed(&self) -> bool {
        self.placed() || self.name == "removed" && !temporary(&self.path)
    }
}

/// Run `operation` and return its checkpoints. Rename and link checkpoints
/// name only the target, so the entry put in place is found by its inode.
fn trace(operation: impl FnOnce()) -> Vec<Event> {
    let events = Rc::new(RefCell::new(Vec::new()));
    let recorded = Rc::clone(&events);
    let mut entries = Vec::new();
    fsio::with_hook(
        Box::new(move |name, path| {
            let mut moved = None;
            match name {
                "rename" | "publication" | "link" => entries = inodes(parent(path)),
                "renamed" | "published" | "linked" => {
                    let target = fs::symlink_metadata(path).unwrap();
                    let (source, _) = entries
                        .iter()
                        .find(|(_, inode)| *inode == target.ino())
                        .expect("the entry put in place was in the target's directory");
                    moved = Some(Moved {
                        path: source.clone(),
                        dir: target.is_dir().then_some(target.ino()),
                    });
                }
                _ => {}
            }
            let dir = match name {
                "directory-flushed" => Some(inode(path)),
                "renamed" | "published" | "linked" | "removed" => Some(inode(parent(path))),
                _ => None,
            };
            recorded.borrow_mut().push(Event {
                name: name.to_owned(),
                path: path.to_owned(),
                dir,
                moved,
            });
            Ok(())
        }),
        operation,
    );
    events.take()
}

/// Check `events` against the rules, returning the first violation of each
/// and noting every rule that had something to check.
fn check(scratch: &Path, events: &[Event], exercised: &mut BTreeSet<&'static str>) -> Vec<String> {
    let show = |path: &Path| shown(scratch, path);
    let flushed = |dir: Option<u64>, range: Range<usize>| {
        events[range]
            .iter()
            .any(|event| event.name == "directory-flushed" && event.dir == dir)
    };
    // What was put in place before `index` without a flush of its directory
    // since.
    let unflushed = |index: usize| {
        events[..index]
            .iter()
            .enumerate()
            .filter(|&(at, event)| event.placed() && !flushed(event.dir, at + 1..index))
            .map(|(_, event)| show(&event.path))
            .collect::<Vec<_>>()
    };
    let mut first = BTreeMap::new();
    let mut fail = |rule: &'static str, violation: String| {
        first.entry(rule).or_insert(violation);
    };
    for (at, event) in events.iter().enumerate() {
        if let Some(moved) = &event.moved {
            if moved.dir.is_some() {
                exercised.insert(NAMESPACE_FLUSHED);
                let changed = events[..at]
                    .iter()
                    .rposition(|earlier| earlier.changed() && earlier.dir == moved.dir);
                if !flushed(moved.dir, changed.map_or(0, |changed| changed + 1)..at) {
                    fail(
                        NAMESPACE_FLUSHED,
                        format!(
                            "{} became {} before it was flushed after its last change",
                            show(&moved.path),
                            show(&event.path)
                        ),
                    );
                }
            } else {
                exercised.insert(FLUSHED_BEFORE_PLACED);
                let written = events[..at]
                    .iter()
                    .rposition(|earlier| earlier.is("written", &moved.path));
                if !written.is_some_and(|written| {
                    events[written..at]
                        .iter()
                        .any(|later| later.is("file-flushed", &moved.path))
                }) {
                    fail(
                        FLUSHED_BEFORE_PLACED,
                        format!(
                            "{} became {} without a flush after it was written",
                            show(&moved.path),
                            show(&event.path)
                        ),
                    );
                }
            }
        }
        if event.name == "publication" {
            exercised.insert(MEMBERSHIP_LAST);
            let earlier = unflushed(at);
            if !earlier.is_empty() {
                fail(
                    MEMBERSHIP_LAST,
                    format!(
                        "{} was published before the directory holding {} was flushed",
                        show(&event.path),
                        earlier.join(", ")
                    ),
                );
            }
            if let Some(later) = events[at..]
                .iter()
                .find(|later| later.placed() && is_record(&later.path))
            {
                fail(
                    MEMBERSHIP_LAST,
                    format!(
                        "{} was put in place after {} was published",
                        show(&later.path),
                        show(&event.path)
                    ),
                );
            }
        }
        let removal = match event.name.as_str() {
            "cleanup" => Some("cleanup of"),
            "remove" if !temporary(&event.path) => Some("removal of"),
            _ => None,
        };
        if let Some(removal) = removal {
            exercised.insert(DURABLE_BEFORE_REMOVAL);
            let earlier = unflushed(at);
            if !earlier.is_empty() {
                fail(
                    DURABLE_BEFORE_REMOVAL,
                    format!(
                        "{removal} {} began before the directory holding {} was flushed",
                        show(&event.path),
                        earlier.join(", ")
                    ),
                );
            }
        }
    }
    exercised.insert(DURABLE_BEFORE_RETURN);
    for (at, event) in events.iter().enumerate() {
        if event.changed() && !flushed(event.dir, at + 1..events.len()) {
            fail(
                DURABLE_BEFORE_RETURN,
                format!(
                    "the directory holding {} was not flushed after it changed",
                    show(&event.path)
                ),
            );
        }
    }
    first
        .into_iter()
        .map(|(rule, violation)| format!("{rule}: {violation}"))
        .collect()
}

fn inode(path: &Path) -> u64 {
    fs::symlink_metadata(path).unwrap().ino()
}

/// The entries of `dir` with their inode numbers.
fn inodes(dir: &Path) -> Vec<(PathBuf, u64)> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let inode = inode(&path);
            (path, inode)
        })
        .collect()
}

fn parent(path: &Path) -> &Path {
    path.parent().unwrap()
}

fn temporary(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with(fsio::TEMP_PREFIX))
}

fn is_record(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_credential_file_name)
}

/// `path` below the scratch directory, with credential file names shortened.
fn shown(scratch: &Path, path: &Path) -> String {
    path.strip_prefix(scratch)
        .unwrap_or(path)
        .iter()
        .map(|part| {
            let part = part.to_string_lossy();
            if is_credential_file_name(&part) {
                format!("{}…", &part[..8])
            } else {
                part.into_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

const RP: &str = "example.com";

fn credential(id: &[u8], user: u8) -> CredentialRecord {
    CredentialRecord {
        credential_id: id.to_vec(),
        rp_id: RP.into(),
        user_id: vec![user],
        user_name: None,
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

/// The record after a signature, as a counter update writes it.
fn used(id: &[u8], user: u8) -> CredentialRecord {
    let mut record = credential(id, user);
    record.sign_count = 1;
    record
}

fn pin() -> PinStateRecord {
    let mut pin = PinStateRecord::default();
    pin.pin_hash = Some([0x42; 16]);
    pin.always_uv = true;
    pin
}

fn attestation() -> AttestationRecord {
    AttestationRecord {
        private_key: [0x41; 32],
        certificate_chain: vec![vec![0x30, 0x00]],
    }
}

fn committed(commit: Result<CredentialCommit, StoreError>) {
    assert_eq!(
        commit.unwrap(),
        CredentialCommit {
            durability: CommitDurability::Flushed,
            cleanup_pending: false,
        }
    );
}

fn reset(store: &mut FileStore) {
    assert_eq!(store.clear().unwrap(), CommitDurability::Flushed);
}

fn fresh(path: &Path) -> FileStore {
    FileStore::open(path).unwrap()
}

/// A store in the legacy layout with two records.
fn legacy(path: &Path) -> FileStore {
    let mut store = fresh(path);
    store.put(&credential(b"kept", 1)).unwrap();
    store.put(&credential(b"retired", 2)).unwrap();
    store
}

/// The legacy store, migrated by a registration: it holds two migrated
/// records and a managed one.
fn managed(path: &Path) -> FileStore {
    let mut store = legacy(path);
    committed(store.insert_or_replace_discoverable(&credential(b"managed", 3)));
    store
}

/// A store whose reset also replaces PIN state and removes the signature
/// counter and the large-blob array.
fn provisioned(mut store: FileStore) -> FileStore {
    store.set_pin_state(&pin()).unwrap();
    store.set_signature_counter(2).unwrap();
    store
        .set_large_blob_array(&INITIAL_LARGE_BLOB_ARRAY)
        .unwrap();
    store
}

/// A legacy store whose migration failed after writing the format marker, so
/// that its reset removes the legacy namespace.
fn interrupted(path: &Path) -> FileStore {
    let mut store = legacy(path);
    let result = fsio::with_hook(
        Box::new(|name, path| {
            if name == "renamed" && path.ends_with(FORMAT_FILE) {
                Err(fsio::io_error(path, std::io::Error::other("interrupted")))
            } else {
                Ok(())
            }
        }),
        || store.insert_or_replace_discoverable(&credential(b"successor", 2)),
    );
    assert!(result.is_err());
    store
}
