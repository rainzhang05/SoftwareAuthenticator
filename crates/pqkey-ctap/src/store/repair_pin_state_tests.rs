//! Errors and process exits at every checkpoint of a repair that replaces a
//! damaged PIN state, large-blob array or both, through the checkpoint
//! sweeps of the credential set's repairs (`repair_tests`).

use std::collections::BTreeMap;

use super::*;
use crate::store::file::repair_tests::{
    Scenario, Served, Swept, assert_nothing_lost, errors_at_every_checkpoint,
    exits_at_every_checkpoint, flip_last_byte, managed, plan, served,
};
use crate::store::test_support::{TempDir, copy_tree, files};

/// The files a case damages, and the credential set's damage of a
/// scenario beside them, if any.
#[derive(Clone, Copy, Debug)]
struct Case {
    damaged: &'static [&'static str],
    beside: Option<Scenario>,
}

const BOTH: &[&str] = &[PIN_STATE_FILE, LARGE_BLOBS_FILE];

const CASES: [Case; 5] = [
    Case {
        damaged: BOTH,
        beside: None,
    },
    Case {
        damaged: &[PIN_STATE_FILE],
        beside: None,
    },
    Case {
        damaged: &[LARGE_BLOBS_FILE],
        beside: None,
    },
    Case {
        damaged: BOTH,
        beside: Some(Scenario::Record),
    },
    Case {
        damaged: BOTH,
        beside: Some(Scenario::Counter),
    },
];

/// The damaged store of a case, to be copied for each run, as the
/// credential set's sweeps copy theirs.
struct Template {
    _scratch: TempDir,
    case: Case,
    state: PathBuf,
    before: BTreeMap<PathBuf, Vec<u8>>,
    old: Served,
    repaired: Served,
}

impl Template {
    /// A store with passkeys, a PIN and a large-blob array, damaged as
    /// `case` says.
    fn new(case: Case) -> Self {
        let scratch = TempDir::new();
        let state = scratch.path().join("template");
        match case.beside {
            Some(scenario) => scenario.apply(&state),
            None => {
                let mut store = managed(&state);
                let mut pin = PinStateRecord::default();
                pin.pin_hash = Some([7; 16]);
                store.set_pin_state(&pin).unwrap();
                store
                    .set_large_blob_array(&INITIAL_LARGE_BLOB_ARRAY)
                    .unwrap();
            }
        }
        for file in case.damaged {
            flip_last_byte(&state.join(file));
        }
        let before = files(&state);
        let old = served(&state);
        let copy = scratch.path().join("repaired");
        copy_tree(&state, &copy);
        FileStore::repair_in(&copy, &plan(&copy)).unwrap();
        let repaired = served(&copy);
        Self {
            _scratch: scratch,
            case,
            state,
            before,
            old,
            repaired,
        }
    }

    /// Whether `file`, which the case damages, is replaced in `state`: by
    /// the PIN state repair writes, or for the large-blob array by none,
    /// which reads as the initial array.  Otherwise it is the damaged file,
    /// in its place: never missing, and never anything else.
    #[track_caller]
    fn replaced(&self, state: &Path, file: &str, context: &str) -> bool {
        let store = FileStore::unopened(state);
        match fs::read(state.join(file)) {
            Ok(contents) if contents == self.before[Path::new(file)] => false,
            _ if file == PIN_STATE_FILE => {
                let mut new = PinStateRecord::default();
                new.always_uv = true;
                assert_eq!(store.pin_state().unwrap(), Some(new), "{context}");
                true
            }
            Ok(_) => panic!("{context}: {file} is neither the damaged file nor removed"),
            Err(err) => {
                assert_eq!(err.kind(), ErrorKind::NotFound, "{context}: {file}");
                let array = store.large_blob_array().unwrap();
                assert_eq!(array, INITIAL_LARGE_BLOB_ARRAY, "{context}");
                true
            }
        }
    }
}

impl Swept for Template {
    fn copy(&self, scratch: &TempDir) -> (PathBuf, RepairPlan) {
        let state = scratch.path().join("state");
        copy_tree(&self.state, &state);
        let plan = plan(&state);
        (state, plan)
    }

    /// After a repair that failed or crashed: the store serves its old or
    /// its repaired credentials and counter; each damaged file is in its
    /// place, or replaced, never neither; every file is where it was or in a
    /// quarantine, a replaced one included; the keys, the counter unless the
    /// case damages it, and the PIN state or array it does not damage are
    /// as they were; and repairing again finishes the work.
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
        let damaged = self.case.damaged;
        let replaced = damaged
            .iter()
            .filter(|file| self.replaced(state, file, context))
            .count();
        assert_nothing_lost(&self.before, state, context);
        let counter = self.case.beside.is_some_and(Scenario::rebuilds_counter);
        let after = files(state);
        for path in self.before.keys().filter(|path| {
            path.starts_with(KEYS_DIR)
                || path.as_os_str() == SIGNATURE_COUNTER_FILE && !counter
                || BOTH
                    .iter()
                    .any(|file| path.as_os_str() == *file && !damaged.contains(file))
        }) {
            assert_eq!(
                self.before.get(path),
                after.get(path),
                "{context}: {}",
                path.display()
            );
        }
        if let Some(plan) = FileStore::plan_repair_in(state).unwrap() {
            FileStore::repair_in(state, &plan)
                .unwrap_or_else(|err| panic!("{context}: repairing again: {err}"));
        }
        assert_eq!(served(state), self.repaired, "{context}");
        assert_eq!(FileStore::inspect_in(state).unwrap(), [], "{context}");
        for file in damaged {
            assert!(self.replaced(state, file, context), "{context}: {file}");
        }
        assert_nothing_lost(&self.before, state, context);
        now == self.repaired && replaced == damaged.len()
    }
}

/// An error or a process exit at every checkpoint of a repair that replaces
/// a damaged PIN state, large-blob array or both, alone or beside a damaged
/// record or counter, leaves each damaged file or its replacement in place,
/// never neither, and repairing again finishes.  Each sweep reaches
/// checkpoints before the repair and after it.
#[test]
fn an_error_or_exit_at_every_checkpoint_leaves_the_damaged_file_or_its_replacement() {
    for case in CASES {
        let template = Template::new(case);
        for outcomes in [
            errors_at_every_checkpoint(&template, case),
            exits_at_every_checkpoint(&template, case),
        ] {
            assert!(outcomes.contains(&false), "{case:?}: never before it");
            assert!(outcomes.contains(&true), "{case:?}: never after it");
        }
    }
}

/// The flush after the new PIN state's rename, or after the removal of the
/// array alone, fails: the repair is visible, with unconfirmed durability.
#[test]
fn a_failed_flush_after_the_replacement_is_unconfirmed_durability() {
    for (case, event, file) in [
        (CASES[1], "renamed", PIN_STATE_FILE),
        (CASES[2], "removed", LARGE_BLOBS_FILE),
    ] {
        let template = Template::new(case);
        let scratch = TempDir::new();
        let (state, planned) = template.copy(&scratch);
        let mut armed = false;
        let repaired = fsio::with_hook(
            Box::new(move |name, path| {
                if name == event && path.ends_with(file) {
                    armed = true;
                } else if armed && name == "directory-flush" {
                    armed = false;
                    return Err(fsio::io_error(path, std::io::Error::other("flush fails")));
                }
                Ok(())
            }),
            || FileStore::repair_in(&state, &planned),
        )
        .unwrap();
        let context = format!("{case:?}");
        assert_eq!(
            repaired.durability,
            CommitDurability::Unconfirmed,
            "{context}"
        );
        assert_eq!(FileStore::inspect_in(&state).unwrap(), [], "{context}");
        assert!(template.replaced(&state, file, &context), "{context}");
    }
}
