//! `pqkey repair`: repair a damaged credential store, with the key stopped.
//!
//! The key holds an exclusive lock on its state directory while it runs, so
//! repair refuses while the lock is held, until `pqkey stop` has stopped the
//! key, as `pqkey pin` refuses until `pqkey start` has started it.  Before it
//! asks, it takes the lock itself, and holds it until it is done, so that the
//! key cannot start meanwhile.  It does not stop or start the key itself: the
//! advice that leads here asks for a copy of the state directory first, which
//! needs the key stopped too.  It lists the damage and what it will do, and
//! asks before it changes the store ([`FileStore::plan_repair_in`],
//! [`FileStore::repair_in`]).

use std::{
    io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use pqkey_ctap::store::{
    CommitDurability, FileStore, Membership, RepairPlan, StoreError, damage_consequence,
};

use super::key::{ask, shown_site, shown_user};
use super::output::{errln, outln};
use crate::platform;
use crate::state_lock::{self, StateLock};

/// `pqkey repair`.
pub fn repair(state_dir: &Path, yes: bool) -> io::Result<()> {
    // Planning decrypts every credential: keep them out of core files, and
    // this process out of reach, before any key is read, as `pqkey status`
    // and the key do.
    repair_with(state_dir, yes, platform::disable_core_dumps)
}

/// [`repair`], with `protect` keeping the process's memory out of reach
/// before anything is read; the unit tests leave their own process as it
/// is, and the real binary's test watches the protection come first.
fn repair_with(
    state_dir: &Path,
    yes: bool,
    protect: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    if state_lock::is_locked(state_dir)? {
        return Err(key_running(state_dir));
    }
    protect()?;
    // A store with nothing to repair is left as it is, without even the
    // lock file.
    if planned(state_dir)?.is_none() {
        return nothing_to_repair(state_dir);
    }
    let lock = StateLock::try_acquire(state_dir)?.ok_or_else(|| key_running(state_dir))?;
    // Nothing else can run, so a pid file is left over from a key that did
    // not exit cleanly, and its pid may be another process's by now: remove
    // it, as the key does when it takes the lock, so that `pqkey status` and
    // `pqkey stop` never take that process for the key while repair runs.
    state_lock::remove_pid_file(state_dir, &lock)?;
    state_lock::remove_info_file(state_dir, &lock)?;
    let Some(plan) = planned(state_dir)? else {
        return nothing_to_repair(state_dir);
    };
    for line in plan_lines(state_dir, &plan) {
        outln!("{line}")?;
    }
    if !yes && !ask("Repair the credential store?", false)? {
        errln!("The credential store was not changed.");
        return Ok(());
    }
    let repaired = FileStore::repair_in(state_dir, &plan).map_err(|err| {
        io::Error::other(format!(
            "repairing the credential store failed: {err}. No file of the store is lost: each \
             is still in the store or kept in {}; run `pqkey repair` again",
            state_dir.join("damaged").display()
        ))
    })?;
    for line in repaired_lines(&plan, repaired.quarantine.as_deref(), repaired.durability) {
        outln!("{line}")?;
    }
    Ok(())
}

/// The error for a key that runs, or another process that holds the lock.
fn key_running(state_dir: &Path) -> io::Error {
    let holder = match state_lock::read_pid(state_dir) {
        Ok(Some(pid)) => format!("the key is running (pid {pid})"),
        _ => format!("{} is in use by another pqkey process", state_dir.display()),
    };
    io::Error::new(
        io::ErrorKind::ResourceBusy,
        format!("{holder}; stop the key with `pqkey stop`, then run `pqkey repair` again"),
    )
}

/// The plan to repair the store in `state_dir`, or `None` if there is
/// nothing to repair.  Planning only reads.  What stops it, a file it
/// cannot read or a directory in the counter's place, the error names, and
/// says what to do.
fn planned(state_dir: &Path) -> io::Result<Option<RepairPlan>> {
    FileStore::plan_repair_in(state_dir).map_err(|err| {
        io::Error::other(format!(
            "the credential store cannot be repaired: {err}; it was not changed{}",
            what_to_do(&err, state_dir)
        ))
    })
}

/// What to do about `err`, which stopped the planning of a repair of the
/// store in `state_dir`, as the sentences that follow it.  A directory in
/// the counter's place, which repair cannot replace in one step, and a
/// credential's record that cannot be read are moved out, and an empty file
/// created in their place, which repair takes for damage of its kind; any
/// other path that cannot be read is made readable.  The clock is checked
/// first, since the empty file takes the clock's time, which a repair under
/// a clock that is behind counts above.  Nothing for other errors, which say
/// what to do themselves, or have nothing a user can do.
fn what_to_do(err: &StoreError, state_dir: &Path) -> String {
    let dir = state_dir.display();
    match err {
        StoreError::Io { path, source }
            if source.kind() == io::ErrorKind::IsADirectory
                && *path == state_dir.join("signature-counter") =>
        {
            format!(
                ". Check that the computer's clock is right, then move that directory out of \
                 {dir}, create an empty file in its place and run `pqkey repair` again"
            )
        }
        StoreError::Io { path, source } if source.raw_os_error().is_some() => {
            if is_record(path) {
                format!(
                    ". Make that file readable or, if it cannot be, check that the computer's \
                     clock is right, then move it out of {dir}, create an empty file of the same \
                     name in its place and run `pqkey repair` again"
                )
            } else {
                ". Make that path readable, then run `pqkey repair` again".to_owned()
            }
        }
        _ => String::new(),
    }
}

/// Whether `path` is named as the store names a credential's record: 64
/// lowercase hexadecimal digits.
fn is_record(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.len() == 64
                && name
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
}

fn nothing_to_repair(state_dir: &Path) -> io::Result<()> {
    outln!(
        "Found nothing to repair in the credential store in {}; it was not changed.",
        state_dir.display()
    )
}

/// `n` and `noun`, in the plural unless `n` is 1.
fn count(n: usize, noun: &str) -> String {
    format!("{n} {noun}{}", if n == 1 { "" } else { "s" })
}

/// The credentials a repaired list holds, as "3 passkeys and 1 other
/// credential".
fn kept(plan: &RepairPlan) -> String {
    match (plan.passkeys, plan.others) {
        (0, 0) => "no credentials".to_owned(),
        (passkeys, 0) => count(passkeys, "passkey"),
        (0, others) => format!("no passkeys and {}", count(others, "other credential")),
        (passkeys, others) => format!(
            "{} and {}",
            count(passkeys, "passkey"),
            count(others, "other credential")
        ),
    }
}

/// The warning a rebuilt list needs: only the lost manifest said which
/// records were members.
const COME_BACK: &str = "A passkey that was deleted or replaced, or whose registration failed, \
                         can come back if its record was left behind, alone or beside another \
                         passkey of its account.";

/// What `pqkey repair` prints before it asks: what is damaged, what fails,
/// and what it will do, step by step, with each file and directory it
/// moves into the quarantine.
fn plan_lines(state_dir: &Path, plan: &RepairPlan) -> Vec<String> {
    let dir = state_dir.display();
    let mut lines = vec![format!("The credential store in {dir} is damaged:")];
    lines.extend(plan.damage.iter().map(|damage| format!("  {damage}")));
    lines.push(format!("{}.", sentence(&damage_consequence(&plan.damage))));
    lines.push(String::new());
    lines.push("`pqkey repair` will:".to_owned());
    let lost = plan
        .damage
        .iter()
        .filter(|damage| damage.is_record())
        .count();
    let mut actions = Vec::new();
    match &plan.membership {
        Membership::Rebuilt => actions.push(
            "build a new list of the key's credentials from the records in credential-set that \
             authenticate under its key"
                .to_owned(),
        ),
        Membership::Listed => actions.push(
            "upgrade the store to the authenticated membership format, as registering a passkey \
             would: credentials becomes credential-set, with a list of the credentials kept"
                .to_owned(),
        ),
        Membership::Created(dir) if dir == "credential-set" => {
            actions.push("create credential-set again, with an empty list of credentials".into());
        }
        Membership::Created(dir) => actions.push(format!("create {dir} again, empty")),
        // Kept, Intact, and any later kind that keeps what it can.
        _ => {}
    }
    if lost > 0 && plan.membership != Membership::Rebuilt {
        actions.push(match lost {
            1 => "leave the credential of the record named above out of the key's list".to_owned(),
            n => format!(
                "leave the credentials of the {n} records named above out of the key's list"
            ),
        });
    }
    // A new list, which a rebuild always publishes and a kept one whenever
    // it replaces the manifest, needs the records' directory, which repair
    // creates if it was lost.
    let publishes = plan.membership == Membership::Rebuilt
        || plan
            .moved
            .iter()
            .any(|moved| moved == "credential-set/active");
    if publishes && !state_dir.join("credential-set").join("records").is_dir() {
        actions.push("create credential-set/records again, empty".to_owned());
    }
    for account in &plan.shared {
        let site = shown_site(&account.rp_id).unwrap_or_else(|| "a site".into());
        let owner = match shown_user(&account.user_name, &account.user_display_name) {
            Some(user) => format!("{user} on {site}"),
            None => format!("one account on {site}"),
        };
        actions.push(match account.passkeys {
            2 => format!("keep both passkeys of {owner}"),
            n => format!("keep all {n} passkeys of {owner}"),
        });
    }
    if plan.marker {
        actions.push("write a new credential-format".to_owned());
    }
    let quarantine = state_dir.join("damaged");
    let starts = counted_from(SystemTime::now());
    if plan.counter {
        actions.push(format!(
            "write a new signature-counter that starts {starts}"
        ));
    }
    for raised in &plan.raised {
        actions.push(format!(
            "rewrite {raised} with its counter {starts}, keeping the old one in a new directory \
             in {}: a damaged copy of its record can have counted higher",
            quarantine.display()
        ));
    }
    if !matches!(plan.membership, Membership::Created(_)) {
        let held = plan.passkeys + plan.others;
        actions.push(if held > plan.max_credentials {
            // The store adds a credential only below its limit.
            format!(
                "keep {}, more than the {max} the key has room for: a registration that adds a \
                 credential fails until the key holds fewer than {max}",
                kept(plan),
                max = plan.max_credentials,
            )
        } else {
            format!("keep {}", kept(plan))
        });
    }
    // A raised record has a line of its own: it is rewritten, not deleted.
    let moved: Vec<&String> = plan
        .moved
        .iter()
        .filter(|moved| !plan.raised.contains(moved))
        .collect();
    match moved.as_slice() {
        [] => {}
        [one] => actions.push(format!(
            "move {one} to a new directory in {}, instead of deleting it",
            quarantine.display()
        )),
        _ => actions.push(format!(
            "move these to a new directory in {}, instead of deleting them:",
            quarantine.display()
        )),
    }
    lines.extend(actions.into_iter().map(|action| format!("  - {action}")));
    if moved.len() > 1 {
        lines.extend(moved.iter().map(|moved| format!("      {moved}")));
    }
    if plan.membership == Membership::Rebuilt {
        lines.push(COME_BACK.to_owned());
    }
    lines
}

/// What `pqkey repair` prints once it has repaired the store as `plan` said,
/// moving what it lists to `quarantine`, flushed as `durability` says.
fn repaired_lines(
    plan: &RepairPlan,
    quarantine: Option<&Path>,
    durability: CommitDurability,
) -> Vec<String> {
    let mut lines = vec![format!(
        "The credential store is repaired: the key keeps {}.",
        kept(plan)
    )];
    if let Some(quarantine) = quarantine {
        lines.push(format!(
            "Moved {} to {}.",
            if plan.moved.len() == 1 { "it" } else { "them" },
            quarantine.display()
        ));
    }
    if durability == CommitDurability::Unconfirmed {
        lines.push(
            "Flushing the repair to storage failed, so a power failure can undo it.".to_owned(),
        );
    }
    lines.push("Start the key again with `pqkey start`.".to_owned());
    lines
}

/// Where a counter that repair writes again starts, by the clock at `now`:
/// above the clock's seconds since 1970, unless the clock reads at or past
/// the largest count, 4294967295 (2106-02-07T06:28:15Z), which the store's
/// count rule then leaves out.
fn counted_from(now: SystemTime) -> &'static str {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    if seconds < u64::from(u32::MAX) {
        "above the number of seconds since 1970 by the computer's clock"
    } else {
        "from the counts it reads and the times the store's files last changed, leaving out the \
         computer's clock, which reads past the largest count"
    }
}

/// `text` with its first letter capitalised.
fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::tests::discoverable;
    use crate::test_support::TempDir;
    use pqkey_ctap::CoseAlg;
    use pqkey_ctap::store::CredentialStore;
    use std::{collections::BTreeMap, fs, path::PathBuf};

    /// Every file under `dir`, with its contents, and every directory.
    fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        let mut found = BTreeMap::new();
        let mut dirs = vec![dir.to_path_buf()];
        while let Some(current) = dirs.pop() {
            for entry in fs::read_dir(&current).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path.clone());
                    found.insert(path, None);
                } else {
                    found.insert(path.clone(), Some(fs::read(&path).unwrap()));
                }
            }
        }
        found
    }

    /// Leaves this test process's core-file limit and dumpability alone,
    /// as the other tests' processes need them.
    fn unprotected() -> io::Result<()> {
        Ok(())
    }

    fn flip_last_byte(path: &Path) {
        let mut contents = fs::read(path).unwrap();
        *contents.last_mut().unwrap() ^= 1;
        fs::write(path, contents).unwrap();
    }

    /// A store in `dir` with three passkeys in the managed layout, the last
    /// two registered as makeCredential does, and its damaged manifest.
    fn damaged_manifest(dir: &Path) {
        let mut store = FileStore::open(dir).unwrap();
        store
            .put(&discoverable("example.com", 1, "alice", CoseAlg::ES256))
            .unwrap();
        for (id, name) in [(2, "bob"), (3, "carol")] {
            store
                .insert_or_replace_discoverable(&discoverable(
                    "example.com",
                    id,
                    name,
                    CoseAlg::ES256,
                ))
                .unwrap();
        }
        flip_last_byte(&dir.join("credential-set").join("active"));
    }

    /// While the key holds the state lock, repair refuses, naming the key's
    /// pid and what to do, and changes nothing; so it does while another
    /// process holds it without a pid.
    #[test]
    fn repair_refuses_while_the_key_holds_the_state_lock() {
        let dir = TempDir::new("repair-locked");
        damaged_manifest(dir.path());
        let lock = StateLock::try_acquire(dir.path()).unwrap().unwrap();
        let before = snapshot(dir.path());
        let err = repair_with(dir.path(), true, unprotected).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ResourceBusy);
        assert_eq!(
            err.to_string(),
            format!(
                "{} is in use by another pqkey process; stop the key with `pqkey stop`, then run \
                 `pqkey repair` again",
                dir.path().display()
            )
        );
        state_lock::write_pid_file(dir.path(), &lock).unwrap();
        let before = {
            let mut before = before;
            before.insert(
                dir.path().join(state_lock::PID_FILE),
                Some(fs::read(dir.path().join(state_lock::PID_FILE)).unwrap()),
            );
            before
        };
        let err = repair_with(dir.path(), true, unprotected).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "the key is running (pid {}); stop the key with `pqkey stop`, then run `pqkey \
                 repair` again",
                std::process::id()
            )
        );
        assert_eq!(snapshot(dir.path()), before, "nothing changed");
        drop(lock);
        repair_with(dir.path(), true, unprotected).unwrap();
        assert_eq!(FileStore::inspect_in(dir.path()).unwrap(), []);
        assert_eq!(FileStore::open(dir.path()).unwrap().count().unwrap(), 3);
    }

    /// A store with nothing to repair is left exactly as it is, without the
    /// lock file that taking the lock would create; so is a missing one.
    #[test]
    fn repair_of_a_healthy_store_changes_nothing() {
        let dir = TempDir::new("repair-healthy");
        let missing = dir.path().join("missing");
        repair_with(&missing, true, unprotected).unwrap();
        assert!(!missing.exists());
        let mut store = FileStore::open(dir.path()).unwrap();
        store
            .insert_or_replace_discoverable(&discoverable(
                "example.com",
                1,
                "alice",
                CoseAlg::ES256,
            ))
            .unwrap();
        let before = snapshot(dir.path());
        repair_with(dir.path(), true, unprotected).unwrap();
        assert_eq!(snapshot(dir.path()), before);
        assert!(!dir.path().join(state_lock::LOCK_FILE).exists());
    }

    /// The plan and the result, as printed: what is damaged and what fails,
    /// then each thing repair does, with the account it keeps two passkeys
    /// of named by its user and site and each file it moves, and the warning
    /// a rebuild needs.
    #[test]
    fn a_rebuild_is_printed_with_each_thing_it_does() {
        let dir = TempDir::new("repair-lines");
        let state = dir.path();
        let mut store = FileStore::open(state).unwrap();
        let first = discoverable("example.com", 1, "alice", CoseAlg::ES256);
        store.insert_or_replace_discoverable(&first).unwrap();
        // A second registration of alice's account replaced the first,
        // whose record is left behind, as when cleanup cannot remove it.
        let records = state.join("credential-set").join("records");
        let old = fs::read_dir(&records)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let kept = fs::read(&old).unwrap();
        let mut second = discoverable("example.com", 2, "alice", CoseAlg::ES256);
        second.user_id = first.user_id.clone();
        store.insert_or_replace_discoverable(&second).unwrap();
        fs::write(&old, kept).unwrap();
        flip_last_byte(&state.join("credential-set").join("active"));
        flip_last_byte(&state.join("credential-format"));
        let plan = FileStore::plan_repair_in(state).unwrap().unwrap();
        let shown = state.display();
        assert_eq!(
            plan_lines(state, &plan),
            [
                format!("The credential store in {shown} is damaged:"),
                "  credential-format is corrupt: authentication failed".to_owned(),
                "  credential-set/active is corrupt: authentication failed".to_owned(),
                "The key cannot register, use or list passkeys.".to_owned(),
                String::new(),
                "`pqkey repair` will:".to_owned(),
                "  - build a new list of the key's credentials from the records in credential-set \
                 that authenticate under its key"
                    .to_owned(),
                "  - keep both passkeys of alice (ALICE) on example.com".to_owned(),
                "  - write a new credential-format".to_owned(),
                "  - keep 2 passkeys".to_owned(),
                format!(
                    "  - move these to a new directory in {shown}/damaged, instead of deleting them:"
                ),
                "      credential-format".to_owned(),
                "      credential-set/active".to_owned(),
                "A passkey that was deleted or replaced, or whose registration failed, can come \
                 back if its record was left behind, alone or beside another passkey of its \
                 account."
                    .to_owned(),
            ]
        );
        let repaired = FileStore::repair_in(state, &plan).unwrap();
        let quarantine = repaired.quarantine.clone().unwrap();
        assert_eq!(
            repaired_lines(&plan, Some(&quarantine), repaired.durability),
            [
                "The credential store is repaired: the key keeps 2 passkeys.".to_owned(),
                format!("Moved them to {}.", quarantine.display()),
                "Start the key again with `pqkey start`.".to_owned(),
            ]
        );
        let mut listed: Vec<_> = FileStore::open(state)
            .unwrap()
            .list()
            .unwrap()
            .into_iter()
            .map(|record| record.credential_id.clone())
            .collect();
        listed.sort();
        assert_eq!(
            listed,
            [first.credential_id.clone(), second.credential_id.clone()]
        );
    }

    /// A rebuild that keeps more credentials than the store has room for
    /// says so, and until when a registration that adds one fails; and
    /// three passkeys of one account are named with their number.
    #[test]
    fn a_rebuild_above_the_credential_limit_says_so() {
        let dir = TempDir::new("repair-limit");
        let state = dir.path();
        let mut store = FileStore::open(state).unwrap().with_max_credentials(2);
        let records = state.join("credential-set").join("records");
        let mut left = Vec::new();
        for id in 1..=3 {
            let mut passkey = discoverable("example.com", id, "carol", CoseAlg::ES256);
            passkey.user_id = vec![9];
            let before: Vec<_> = fs::read_dir(&records)
                .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
                .unwrap_or_default();
            store.insert_or_replace_discoverable(&passkey).unwrap();
            let file = fs::read_dir(&records)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| !before.contains(path))
                .unwrap();
            left.push((file.clone(), fs::read(&file).unwrap()));
        }
        // Each replaced record is left behind.
        for (file, contents) in &left {
            fs::write(file, contents).unwrap();
        }
        flip_last_byte(&state.join("credential-set").join("active"));
        let plan = store.plan_repair().unwrap().unwrap();
        let lines = plan_lines(state, &plan);
        assert_eq!(
            lines[6..8],
            [
                "  - keep all 3 passkeys of carol (CAROL) on example.com".to_owned(),
                "  - keep 3 passkeys, more than the 2 the key has room for: a registration that adds \
                 a credential fails until the key holds fewer than 2"
                    .to_owned(),
            ]
        );
    }

    /// A legacy store's damaged records, as printed: the store is upgraded,
    /// the credentials in them are left out of its list, counted, and the
    /// rest kept, with or without others than passkeys, and each moved file
    /// is named; a lost namespace is created again; and what a repair whose
    /// flush failed says.
    #[test]
    fn other_repairs_are_printed_with_what_they_keep() {
        let dir = TempDir::new("repair-records");
        let state = dir.path();
        let mut store = FileStore::open(state).unwrap();
        let mut files = Vec::new();
        for id in 1..=4 {
            let records = state.join("credentials");
            let before: Vec<_> = fs::read_dir(&records)
                .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
                .unwrap_or_default();
            let mut record = discoverable("example.com", id, "user", CoseAlg::ES256);
            if id == 4 {
                // A security key's stored credential.
                record.credential_id[0] = 0x00;
                record.user_id = Vec::new();
            }
            store.put(&record).unwrap();
            files.push(
                fs::read_dir(&records)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| !before.contains(path))
                    .unwrap(),
            );
        }
        flip_last_byte(&files[0]);
        fs::remove_file(&files[1]).unwrap();
        flip_last_byte(&files[2]);
        let plan = FileStore::plan_repair_in(state).unwrap().unwrap();
        let lines = plan_lines(state, &plan);
        let name = |file: &PathBuf| file.file_name().unwrap().to_string_lossy().into_owned();
        let damaged: std::collections::BTreeSet<_> = lines[1..3].iter().cloned().collect();
        assert_eq!(
            damaged,
            [&files[0], &files[2]]
                .into_iter()
                .map(|file| format!(
                    "  credentials/{} is corrupt: authentication failed",
                    name(file)
                ))
                .collect()
        );
        assert_eq!(
            lines[3],
            "The key cannot register passkeys, or use the credentials in those files."
        );
        let mut moved = [name(&files[0]), name(&files[2])];
        moved.sort();
        assert_eq!(
            lines[6..],
            [
                "  - upgrade the store to the authenticated membership format, as registering a \
                 passkey would: credentials becomes credential-set, with a list of the credentials \
                 kept"
                    .to_owned(),
                "  - leave the credentials of the 2 records named above out of the key's list"
                    .to_owned(),
                "  - write a new credential-format".to_owned(),
                "  - keep no passkeys and 1 other credential".to_owned(),
                format!(
                    "  - move these to a new directory in {}/damaged, instead of deleting them:",
                    state.display()
                ),
                format!("      credentials/{}", moved[0]),
                format!("      credentials/{}", moved[1]),
            ]
        );
        FileStore::repair_in(state, &plan).unwrap();
        assert!(state.join("credential-set").join("active").is_file());
        assert!(!state.join("credentials").exists());

        // A lost namespace, which takes its passkeys with it.
        fs::remove_dir_all(state.join("credential-set")).unwrap();
        let plan = FileStore::plan_repair_in(state).unwrap().unwrap();
        assert_eq!(
            plan_lines(state, &plan)[1..],
            [
                "  credential-set is missing".to_owned(),
                "  credentials is missing".to_owned(),
                "The key cannot register, use or list passkeys.".to_owned(),
                String::new(),
                "`pqkey repair` will:".to_owned(),
                "  - create credential-set again, with an empty list of credentials".to_owned(),
            ]
        );
        let repaired = FileStore::repair_in(state, &plan).unwrap();
        assert_eq!(repaired.quarantine, None);
        assert_eq!(
            repaired_lines(&plan, None, CommitDurability::Unconfirmed),
            [
                "The credential store is repaired: the key keeps no credentials.",
                "Flushing the repair to storage failed, so a power failure can undo it.",
                "Start the key again with `pqkey start`.",
            ]
        );
    }

    /// A record lost with its directory, as printed: its credential is left
    /// out of the list, and the directory is created again, empty, for the
    /// list that names the rest, a passkey and a security key's stored
    /// credential.
    #[test]
    fn a_lost_records_directory_is_created_again() {
        let dir = TempDir::new("repair-records-dir");
        let state = dir.path();
        let mut store = FileStore::open(state).unwrap();
        store
            .put(&discoverable("example.com", 1, "alice", CoseAlg::ES256))
            .unwrap();
        // A security key's stored credential.
        let mut stored = discoverable("example.com", 4, "user", CoseAlg::ES256);
        stored.credential_id[0] = 0x00;
        stored.user_id = Vec::new();
        store.put(&stored).unwrap();
        store
            .insert_or_replace_discoverable(&discoverable("example.com", 2, "bob", CoseAlg::ES256))
            .unwrap();
        let records = state.join("credential-set").join("records");
        fs::remove_dir_all(&records).unwrap();
        let plan = FileStore::plan_repair_in(state).unwrap().unwrap();
        let lines = plan_lines(state, &plan);
        assert_eq!(
            lines[2],
            "The key cannot register passkeys, or use the credential in that file."
        );
        assert_eq!(
            lines[4..],
            [
                "`pqkey repair` will:".to_owned(),
                "  - leave the credential of the record named above out of the key's list"
                    .to_owned(),
                "  - create credential-set/records again, empty".to_owned(),
                "  - keep 1 passkey and 1 other credential".to_owned(),
                format!(
                    "  - move credential-set/active to a new directory in {}/damaged, instead of \
                     deleting it",
                    state.display()
                ),
            ]
        );
        FileStore::repair_in(state, &plan).unwrap();
        assert!(records.is_dir());
        assert_eq!(fs::read_dir(&records).unwrap().count(), 0);
    }

    /// A legacy store's lost `credentials` directory, as printed: what fails,
    /// and that repair creates it again, empty, moving nothing.
    #[test]
    fn a_lost_legacy_directory_is_printed_as_created_again() {
        let dir = TempDir::new("repair-legacy-dir");
        let state = dir.path();
        FileStore::open(state)
            .unwrap()
            .put(&discoverable("example.com", 1, "alice", CoseAlg::ES256))
            .unwrap();
        fs::remove_dir_all(state.join("credentials")).unwrap();
        let plan = FileStore::plan_repair_in(state).unwrap().unwrap();
        assert_eq!(
            plan_lines(state, &plan)[1..],
            [
                "  credentials is missing".to_owned(),
                "The key cannot use any passkeys that were in it.".to_owned(),
                String::new(),
                "`pqkey repair` will:".to_owned(),
                "  - create credentials again, empty".to_owned(),
            ]
        );
        let repaired = FileStore::repair_in(state, &plan).unwrap();
        assert_eq!(
            repaired_lines(&plan, repaired.quarantine.as_deref(), repaired.durability),
            [
                "The credential store is repaired: the key keeps no credentials.",
                "Start the key again with `pqkey start`.",
            ]
        );
        assert!(state.join("credentials").is_dir());
    }

    /// An account whose site and user leave nothing printable is named all
    /// the same, as one account on a site.
    #[test]
    fn an_account_with_nothing_printable_is_named_all_the_same() {
        let dir = TempDir::new("repair-unprintable");
        let state = dir.path();
        let mut store = FileStore::open(state).unwrap();
        let unprintable = |id| {
            let mut passkey = discoverable("\u{7}", id, "-", CoseAlg::ES256);
            passkey.user_id = vec![7];
            passkey.user_name = None;
            passkey.user_display_name = None;
            passkey
        };
        store
            .insert_or_replace_discoverable(&unprintable(1))
            .unwrap();
        // The next registration of the account replaces it, and its record
        // is left behind.
        let records = state.join("credential-set").join("records");
        let old = fs::read_dir(&records)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let left = fs::read(&old).unwrap();
        store
            .insert_or_replace_discoverable(&unprintable(2))
            .unwrap();
        fs::write(&old, left).unwrap();
        flip_last_byte(&state.join("credential-set").join("active"));
        let plan = FileStore::plan_repair_in(state).unwrap().unwrap();
        assert_eq!(
            plan_lines(state, &plan)[6],
            "  - keep both passkeys of one account on a site"
        );
    }

    /// A store that planning cannot repair is left as it is, and the error
    /// says why, that the store was not changed, and what to do: a
    /// credential key of the wrong length, whose error says what to do; a
    /// key file or a member's record that cannot be read, which it names; or
    /// a directory in the counter's place, which repair cannot replace in
    /// one step.  Nothing is created, not even the lock file.  Moved out of
    /// the state directory, with an empty file created in its place under
    /// this machine's clock, as the error says, the record is one repair
    /// leaves out of the list, which takes its credential off the key, and
    /// the counter one it writes again.
    #[test]
    fn a_store_repair_cannot_read_is_left_as_it_is() {
        for unreadable in [
            "short key",
            "unreadable key",
            "unreadable record",
            "counter directory",
        ] {
            let dir = TempDir::new("repair-unreadable");
            let state = dir.path();
            let mut store = FileStore::open(state).unwrap();
            store
                .insert_or_replace_discoverable(&discoverable(
                    "example.com",
                    1,
                    "alice",
                    CoseAlg::ES256,
                ))
                .unwrap();
            store.set_signature_counter(5).unwrap();
            let key = state.join("keys").join("credential.key");
            let record = fs::read_dir(state.join("credential-set").join("records"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let counter = state.join("signature-counter");
            let shown = state.display();
            // A directory in a file's place fails reads with EISDIR, as root
            // too.
            let (named, what_to_do) = match unreadable {
                "short key" => {
                    fs::write(&key, b"short").unwrap();
                    (None, String::new())
                }
                "unreadable key" => {
                    fs::remove_file(&key).unwrap();
                    fs::create_dir(&key).unwrap();
                    (
                        Some(&key),
                        ". Make that path readable, then run `pqkey repair` again".to_owned(),
                    )
                }
                "unreadable record" => {
                    fs::remove_file(&record).unwrap();
                    fs::create_dir(&record).unwrap();
                    (
                        Some(&record),
                        format!(
                            ". Make that file readable or, if it cannot be, check that the \
                             computer's clock is right, then move it out of {shown}, create an \
                             empty file of the same name in its place and run `pqkey repair` again"
                        ),
                    )
                }
                _ => {
                    fs::remove_file(&counter).unwrap();
                    fs::create_dir(&counter).unwrap();
                    (
                        Some(&counter),
                        format!(
                            ". Check that the computer's clock is right, then move that \
                             directory out of {shown}, create an empty file in its place and run \
                             `pqkey repair` again"
                        ),
                    )
                }
            };
            let cause = FileStore::plan_repair_in(state).unwrap_err();
            let before = snapshot(state);
            let err = repair_with(state, true, unprotected).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(
                    "the credential store cannot be repaired: {cause}; it was not \
                     changed{what_to_do}"
                ),
                "{unreadable}"
            );
            if let Some(named) = named {
                assert!(
                    err.to_string().contains(&format!("{}: ", named.display())),
                    "{unreadable}: {err}"
                );
            }
            assert_eq!(snapshot(state), before, "{unreadable}");
            assert!(!state.join(state_lock::LOCK_FILE).exists(), "{unreadable}");
            if let Some(moved) = named.filter(|_| unreadable != "unreadable key") {
                let outside = TempDir::new("repair-moved-out");
                fs::rename(moved, outside.path().join("moved")).unwrap();
                fs::write(moved, b"").unwrap();
                let since_1970 = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                repair_with(state, true, unprotected).unwrap();
                assert_eq!(FileStore::inspect_in(state).unwrap(), [], "{unreadable}");
                let store = FileStore::open(state).unwrap();
                if moved == &record {
                    assert_eq!(store.count().unwrap(), 0, "{unreadable}");
                } else {
                    assert_eq!(store.count().unwrap(), 1, "{unreadable}");
                    let count = store.signature_counter().unwrap();
                    assert!(u64::from(count) > since_1970, "{count} <= {since_1970}");
                }
            }
        }
    }

    /// A record repair could not read, moved out of the state directory with
    /// an empty file created in its place, as repair's refusal says, is damage
    /// repair handles, with or without a copy in the other record directory,
    /// in an intact list and in a rebuild, and the plan says what follows.
    /// In an intact list the member is a directory, which fails reads with
    /// EISDIR, as root too: its credential is left out, and a copy of it
    /// elsewhere, which the list does not name, is moved out of the store
    /// too.  A rebuild reads only regular files, so only an unreadable one
    /// stops it (EACCES or EIO, which a test running as root cannot make):
    /// here the empty file is in place already.  Without a copy, the
    /// credential is left out; with an intact copy, the copy is kept and its
    /// count raised.
    #[test]
    fn an_unreadable_record_is_repaired_once_an_empty_file_takes_its_place() {
        for (rebuild, copy) in [(false, false), (false, true), (true, false), (true, true)] {
            let context = format!("rebuild {rebuild}, copy {copy}");
            let dir = TempDir::new("repair-empty-record");
            let state = dir.path();
            let shown = state.display();
            let mut store = FileStore::open(state).unwrap();
            // Stored before the upgrade, which keeps its record in
            // credential-set/.
            let first = discoverable("example.com", 1, "alice", CoseAlg::ES256);
            store.put(&first).unwrap();
            store
                .insert_or_replace_discoverable(&discoverable(
                    "example.com",
                    2,
                    "bob",
                    CoseAlg::ES256,
                ))
                .unwrap();
            let set = state.join("credential-set");
            let migrated = fs::read_dir(&set)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| is_record(path))
                .unwrap();
            let name = migrated.file_name().unwrap().to_string_lossy().into_owned();
            let other = set.join("records").join(&name);
            if copy {
                // It fails authentication there, under the other logical
                // name.
                fs::copy(&migrated, &other).unwrap();
            }
            // In a rebuild with a copy, the copy is the record that cannot
            // be read, and the migrated one the intact copy repair keeps.
            let unreadable = if rebuild && copy { &other } else { &migrated };
            if rebuild {
                flip_last_byte(&set.join("active"));
            } else {
                fs::remove_file(unreadable).unwrap();
                fs::create_dir(unreadable).unwrap();
                let err = repair_with(state, true, unprotected).unwrap_err();
                assert!(
                    err.to_string().ends_with(&format!(
                        "; it was not changed. Make that file readable or, if it cannot be, check \
                         that the computer's clock is right, then move it out of {shown}, create \
                         an empty file of the same name in its place and run `pqkey repair` again"
                    )),
                    "{context}: {err}"
                );
                let outside = TempDir::new("repair-moved-out");
                fs::rename(unreadable, outside.path().join("moved")).unwrap();
            }
            fs::write(unreadable, b"").unwrap();
            let plan = FileStore::plan_repair_in(state).unwrap().unwrap();
            let lines = plan_lines(state, &plan);
            let relative = unreadable
                .strip_prefix(state)
                .unwrap()
                .display()
                .to_string();
            assert!(
                lines.contains(&format!("  {relative} is corrupt: invalid length")),
                "{context}: {lines:#?}"
            );
            let raise = format!(
                "  - rewrite credential-set/{name} with its counter above the number of seconds \
                 since 1970 by the computer's clock, keeping the old one in a new directory in \
                 {shown}/damaged: a damaged copy of its record can have counted higher"
            );
            assert_eq!(
                lines.contains(&raise),
                rebuild && copy,
                "{context}: {lines:#?}"
            );
            if !rebuild {
                assert!(
                    lines.contains(
                        &"  - leave the credential of the record named above out of the key's list"
                            .to_owned()
                    ),
                    "{context}: {lines:#?}"
                );
            }
            let since_1970 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            FileStore::repair_in(state, &plan).unwrap();
            assert_eq!(FileStore::inspect_in(state).unwrap(), [], "{context}");
            let kept = FileStore::open(state)
                .unwrap()
                .get(&first.credential_id)
                .unwrap();
            if rebuild && copy {
                let count = kept.unwrap().sign_count;
                assert!(u64::from(count) > since_1970, "{context}: {count}");
            } else {
                assert_eq!(kept, None, "{context}");
            }
        }
    }

    /// A lost count, as printed: what fails, that repair writes a new
    /// counter above the seconds since 1970, which it does, and the files it
    /// moves.  A rebuild that keeps one copy of a record while another is
    /// damaged starts that credential's counter above them too.
    #[test]
    fn a_lost_count_is_printed_with_what_repair_writes_again() {
        let since_1970 = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };
        let dir = TempDir::new("repair-counter");
        let state = dir.path();
        let shown = state.display();
        let mut store = FileStore::open(state).unwrap();
        // The first passkey is stored before the upgrade, which keeps its
        // record in credential-set/.
        let first = discoverable("example.com", 1, "alice", CoseAlg::ES256);
        store.put(&first).unwrap();
        store
            .insert_or_replace_discoverable(&discoverable("example.com", 2, "bob", CoseAlg::ES256))
            .unwrap();
        store.set_signature_counter(5).unwrap();
        flip_last_byte(&state.join("signature-counter"));
        let plan = FileStore::plan_repair_in(state).unwrap().unwrap();
        assert_eq!(
            plan_lines(state, &plan),
            [
                format!("The credential store in {shown} is damaged:"),
                "  signature-counter is corrupt: authentication failed".to_owned(),
                "The key cannot sign in to sites that registered it as a security key and whose \
                 credentials it did not store."
                    .to_owned(),
                String::new(),
                "`pqkey repair` will:".to_owned(),
                "  - write a new signature-counter that starts above the number of seconds since \
                 1970 by the computer's clock"
                    .to_owned(),
                "  - keep 2 passkeys".to_owned(),
                format!(
                    "  - move signature-counter to a new directory in {shown}/damaged, instead of \
                     deleting it"
                ),
            ]
        );
        let before = since_1970();
        let repaired = FileStore::repair_in(state, &plan).unwrap();
        let quarantine = repaired.quarantine.clone().unwrap();
        assert_eq!(
            repaired_lines(&plan, Some(&quarantine), repaired.durability),
            [
                "The credential store is repaired: the key keeps 2 passkeys.".to_owned(),
                format!("Moved it to {}.", quarantine.display()),
                "Start the key again with `pqkey start`.".to_owned(),
            ]
        );
        let count = FileStore::open(state).unwrap().signature_counter().unwrap();
        assert!(u64::from(count) > before, "{count} <= {before}");

        // A copy of the first passkey's record among the managed ones fails
        // authentication there, and the list is damaged.
        let set = state.join("credential-set");
        let migrated = fs::read_dir(&set)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| is_record(path))
            .unwrap();
        let name = migrated.file_name().unwrap().to_string_lossy().into_owned();
        fs::copy(&migrated, set.join("records").join(&name)).unwrap();
        flip_last_byte(&set.join("active"));
        let plan = FileStore::plan_repair_in(state).unwrap().unwrap();
        // The raised record has a line of its own, and is not among the
        // files moved instead of being deleted.
        assert_eq!(
            plan_lines(state, &plan)[5..],
            [
                "`pqkey repair` will:".to_owned(),
                "  - build a new list of the key's credentials from the records in credential-set \
                 that authenticate under its key"
                    .to_owned(),
                format!(
                    "  - rewrite credential-set/{name} with its counter above the number of seconds \
                     since 1970 by the computer's clock, keeping the old one in a new directory in \
                     {shown}/damaged: a damaged copy of its record can have counted higher"
                ),
                "  - keep 2 passkeys".to_owned(),
                format!(
                    "  - move these to a new directory in {shown}/damaged, instead of deleting them:"
                ),
                "      credential-set/active".to_owned(),
                format!("      credential-set/records/{name}"),
                COME_BACK.to_owned(),
            ]
        );
        let before = since_1970();
        FileStore::repair_in(state, &plan).unwrap();
        let first = FileStore::open(state)
            .unwrap()
            .get(&first.credential_id)
            .unwrap()
            .unwrap();
        assert!(u64::from(first.sign_count) > before, "{}", first.sign_count);
    }

    /// A clock at or past the largest count, which the store's count rule
    /// leaves out, is not claimed to be below the new count.
    #[test]
    fn a_count_starts_above_the_clock_only_while_the_clock_is_below_the_largest_count() {
        let at = |seconds| UNIX_EPOCH + std::time::Duration::from_secs(seconds);
        for seconds in [0, 1_794_500_000, u64::from(u32::MAX) - 1] {
            assert_eq!(
                counted_from(at(seconds)),
                "above the number of seconds since 1970 by the computer's clock"
            );
        }
        for seconds in [u64::from(u32::MAX), 7_258_118_400] {
            assert_eq!(
                counted_from(at(seconds)),
                "from the counts it reads and the times the store's files last changed, leaving \
                 out the computer's clock, which reads past the largest count"
            );
        }
    }

    /// What to do about each error that stops a repair's planning: a record
    /// or a path that cannot be read, whatever the system call's error, and
    /// a directory in the counter's place; and nothing for an error without
    /// one, such as a store that kept changing while it was checked.
    #[test]
    fn what_to_do_follows_the_error_that_stopped_planning() {
        let state = Path::new("/state");
        let failed = |path: &str, source| StoreError::Io {
            path: state.join(path),
            source,
        };
        let record = "credential-set/records/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        for code in [5, 13, 21] {
            assert_eq!(
                what_to_do(&failed(record, io::Error::from_raw_os_error(code)), state),
                ". Make that file readable or, if it cannot be, check that the computer's clock is \
                 right, then move it out of /state, create an empty file of the same name in its \
                 place and run `pqkey repair` again",
                "{code}"
            );
            assert_eq!(
                what_to_do(
                    &failed("keys/credential.key", io::Error::from_raw_os_error(code)),
                    state
                ),
                ". Make that path readable, then run `pqkey repair` again",
                "{code}"
            );
        }
        assert_eq!(
            what_to_do(
                &failed(
                    "signature-counter",
                    io::Error::new(io::ErrorKind::IsADirectory, "is a directory")
                ),
                state
            ),
            ". Check that the computer's clock is right, then move that directory out of /state, \
             create an empty file in its place and run `pqkey repair` again"
        );
        let unsettled = StoreError::Io {
            path: state.to_path_buf(),
            source: io::Error::other("it kept changing while it was checked"),
        };
        assert_eq!(what_to_do(&unsettled, state), "");
        assert_eq!(what_to_do(&StoreError::Random, state), "");
    }

    #[test]
    fn counts_are_said_in_words() {
        assert_eq!(count(1, "file"), "1 file");
        assert_eq!(count(2, "file"), "2 files");
        assert_eq!(count(0, "passkey"), "0 passkeys");
    }
}
