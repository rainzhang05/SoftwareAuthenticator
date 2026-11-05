//! The `pqkey` binary on a damaged credential store, given with
//! `--state-dir`: `pqkey status` names the damage and the fix, `pqkey repair`
//! says what it will do, asks, repairs, and refuses while the key holds the
//! state lock; both turn core files off before they read a key.
#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    env, fs,
    io::{ErrorKind, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::Duration,
};

use nix::sys::resource::{Resource, getrlimit, setrlimit};
use pqkey::state_lock::{self, StateLock};
use pqkey_ctap::CoseAlg;
use pqkey_ctap::store::{CredentialRecord, CredentialStore, FileStore, PrivateKeyMaterial};

/// A state directory of the test's own, which no key runs on.
struct State(PathBuf);

impl State {
    fn new(name: &str) -> Self {
        let dir = env::temp_dir().join(format!("pqkey-damaged-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Self(dir)
    }
}

impl Drop for State {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn passkey(user: u8) -> CredentialRecord {
    CredentialRecord {
        credential_id: [vec![1], vec![user; 32]].concat(),
        rp_id: "example.com".into(),
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

/// A store in `dir` with three passkeys registered as makeCredential
/// registers them, whose manifest, `credential-set/active`, then fails
/// authentication: probe B3.
fn damaged(dir: &Path) {
    let mut store = FileStore::open(dir).unwrap();
    for user in 1..=3 {
        store
            .insert_or_replace_discoverable(&passkey(user))
            .unwrap();
    }
    let active = dir.join("credential-set").join("active");
    let mut contents = fs::read(&active).unwrap();
    *contents.last_mut().unwrap() ^= 1;
    fs::write(&active, contents).unwrap();
}

/// Every file under `dir` with its contents.
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
                found.insert(path.clone(), fs::read(&path).unwrap());
            }
        }
    }
    found
}

fn pqkey(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pqkey"));
    command
        .arg("--state-dir")
        .arg(dir)
        .args(args)
        .env_remove("PQKEY_STATE_DIR")
        .env("NO_COLOR", "1");
    command
}

/// Run `pqkey ARGS` on `dir` with `input` on standard input.
fn run(dir: &Path, args: &[&str], input: &str) -> Output {
    let mut child = pqkey(dir, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// What `pqkey repair` prints for the store of [`damaged`] in `dir`.
fn plan(dir: &Path) -> String {
    let shown = dir.display();
    format!(
        "The credential store in {shown} is damaged:\n\
         \x20 credential-set/active is corrupt: authentication failed\n\
         The key cannot register, use or list passkeys.\n\
         \n\
         `pqkey repair` will:\n\
         \x20 - build a new list of the key's credentials from the records in credential-set \
         that authenticate under its key\n\
         \x20 - keep 3 passkeys\n\
         \x20 - move credential-set/active to a new directory in {shown}/damaged, instead of \
         deleting it\n\
         A passkey that was deleted or replaced, or whose registration failed, can come back if \
         its record was left behind, alone or beside another passkey of its account.\n"
    )
}

/// `pqkey status` names the damage and what to do; `pqkey repair` says what
/// it will do, changes no file of the store on a no, and repairs on `--yes`,
/// moving the damaged manifest, byte for byte, into its quarantine; then
/// `pqkey status` has nothing to say about the store, which serves all three
/// passkeys.
#[test]
fn status_names_the_damage_and_repair_repairs_it() {
    let state = State::new("repair");
    let dir = &state.0;
    damaged(dir);
    let manifest = fs::read(dir.join("credential-set").join("active")).unwrap();

    let status = run(dir, &["status"], "");
    assert_eq!(status.status.code(), Some(0), "{status:?}");
    let out = text(&status.stdout);
    let problem = format!(
        "\n  ! the credential store is damaged (credential-set/active is corrupt: authentication \
         failed): the key cannot register, use or list passkeys\n    Fix: stop the key with \
         `pqkey stop`, keep a copy of {}, run `pqkey repair`, then start the key again with \
         `pqkey start`; `pqkey reset` erases every passkey, so use it only as a last resort\n",
        dir.display()
    );
    assert!(out.contains(&problem), "{out}");

    let before = files(dir);
    let declined = run(dir, &["repair"], "n\n");
    assert_eq!(declined.status.code(), Some(0), "{declined:?}");
    assert_eq!(text(&declined.stdout), plan(dir));
    assert_eq!(
        text(&declined.stderr),
        "Repair the credential store? [y/N] The credential store was not changed.\n"
    );
    let mut after = files(dir);
    // Only the lock repair took before it asked.
    assert_eq!(
        after.remove(&dir.join(state_lock::LOCK_FILE)),
        Some(Vec::new())
    );
    assert_eq!(after, before);

    let repaired = run(dir, &["repair", "--yes"], "");
    assert_eq!(repaired.status.code(), Some(0), "{repaired:?}");
    assert_eq!(text(&repaired.stderr), "");
    let quarantines: Vec<_> = fs::read_dir(dir.join("damaged"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    let [quarantine] = quarantines.as_slice() else {
        panic!("one quarantine: {quarantines:?}");
    };
    assert_eq!(
        text(&repaired.stdout),
        format!(
            "{}The credential store is repaired: the key keeps 3 passkeys.\n\
             Moved it to {}.\n\
             Start the key again with `pqkey start`.\n",
            plan(dir),
            quarantine.display()
        )
    );
    assert_eq!(
        fs::read(quarantine.join("credential-set").join("active")).unwrap(),
        manifest
    );

    let status = run(dir, &["status"], "");
    assert_eq!(status.status.code(), Some(0), "{status:?}");
    assert!(
        !text(&status.stdout).contains("credential store"),
        "{status:?}"
    );
    let ids: Vec<_> = FileStore::open(dir)
        .unwrap()
        .list()
        .unwrap()
        .into_iter()
        .map(|record| record.credential_id.clone())
        .collect();
    assert_eq!(
        ids,
        [3, 2, 1].map(|user| passkey(user).credential_id.clone())
    );
    let repeated = run(dir, &["repair"], "");
    assert_eq!(
        text(&repeated.stdout),
        format!(
            "Found nothing to repair in the credential store in {}; it was not changed.\n",
            dir.display()
        )
    );
}

/// While the key holds the state lock, `pqkey repair` refuses, naming it,
/// and changes nothing.  A store that is not damaged is left as it is, even
/// without a lock file.
#[test]
fn repair_refuses_while_the_key_runs_and_leaves_a_healthy_store_alone() {
    let state = State::new("refuse");
    let dir = &state.0;
    damaged(dir);
    let lock = StateLock::try_acquire(dir).unwrap().unwrap();
    state_lock::write_pid_file(dir, &lock).unwrap();
    let before = files(dir);
    let refused = run(dir, &["repair", "--yes"], "");
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert_eq!(
        text(&refused.stderr),
        format!(
            "pqkey: the key is running (pid {}); stop the key with `pqkey stop`, then run `pqkey \
             repair` again\n",
            std::process::id()
        )
    );
    assert_eq!(text(&refused.stdout), "");
    assert_eq!(files(dir), before);
    drop(lock);

    let state = State::new("healthy");
    let dir = &state.0;
    FileStore::open(dir)
        .unwrap()
        .insert_or_replace_discoverable(&passkey(1))
        .unwrap();
    let before = files(dir);
    let healthy = run(dir, &["repair"], "");
    assert_eq!(healthy.status.code(), Some(0), "{healthy:?}");
    assert_eq!(
        text(&healthy.stdout),
        format!(
            "Found nothing to repair in the credential store in {}; it was not changed.\n",
            dir.display()
        )
    );
    assert_eq!(files(dir), before);
}

/// A key killed without cleaning up leaves its pid file behind, and by now
/// that pid can be another process's.  Repair takes the state lock as the
/// key does, so it removes that file and the key's information file first,
/// as the key does: while repair waits at its question, `pqkey status` does
/// not take the other process for the key, `pqkey stop` does not signal it,
/// and afterwards the key is not running.
#[test]
fn repair_removes_a_stale_pid_file_before_it_asks() {
    use std::io::Read;
    let state = State::new("stale");
    let dir = &state.0;
    damaged(dir);
    let mut other = Command::new("sleep").arg("60").spawn().unwrap();
    fs::write(dir.join(state_lock::PID_FILE), format!("{}\n", other.id())).unwrap();
    fs::write(dir.join(state_lock::INFO_FILE), b"left behind").unwrap();
    assert!(
        text(&run(dir, &["status"], "").stdout).starts_with("Key:      not running"),
        "without the lock the pid file is not trusted"
    );
    let mut repair = pqkey(dir, &["repair"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Repair asks with the lock held.
    let mut stderr = repair.stderr.take().unwrap();
    let mut asked = Vec::new();
    while !asked.ends_with(b"[y/N] ") {
        let mut byte = [0];
        assert_eq!(
            stderr.read(&mut byte).unwrap(),
            1,
            "repair ended before it asked"
        );
        asked.push(byte[0]);
    }
    assert!(!dir.join(state_lock::PID_FILE).exists());
    assert!(!dir.join(state_lock::INFO_FILE).exists());
    let status = run(dir, &["status"], "");
    assert_eq!(
        text(&status.stdout),
        "Key:      starting or stopping\n",
        "{status:?}"
    );
    let stop = run(dir, &["stop"], "");
    assert_eq!(stop.status.code(), Some(1), "{stop:?}");
    assert!(
        other.try_wait().unwrap().is_none(),
        "the other process was not signalled"
    );
    repair.stdin.take().unwrap().write_all(b"n\n").unwrap();
    let declined = repair.wait_with_output().unwrap();
    assert_eq!(declined.status.code(), Some(0), "{declined:?}");
    assert!(!dir.join(state_lock::PID_FILE).exists());
    assert!(text(&run(dir, &["status"], "").stdout).starts_with("Key:      not running"));
    other.kill().unwrap();
    other.wait().unwrap();
}

/// A store that changes while repair waits at its question is not
/// repaired: the repair plans again and finds a different plan, changes no
/// file, and says that no file of the store is lost; running repair again
/// repairs the store as it is now.
#[test]
fn a_store_that_changes_at_the_question_is_not_repaired() {
    use std::io::Read;
    let state = State::new("changed");
    let dir = &state.0;
    damaged(dir);
    let mut repair = pqkey(dir, &["repair"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = repair.stderr.take().unwrap();
    let mut asked = Vec::new();
    while !asked.ends_with(b"[y/N] ") {
        let mut byte = [0];
        assert_eq!(
            stderr.read(&mut byte).unwrap(),
            1,
            "repair ended before it asked"
        );
        asked.push(byte[0]);
    }
    // Meanwhile a record fails authentication too.
    let record = fs::read_dir(dir.join("credential-set").join("records"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut contents = fs::read(&record).unwrap();
    *contents.last_mut().unwrap() ^= 1;
    fs::write(&record, contents).unwrap();
    let before = files(dir);
    repair.stdin.take().unwrap().write_all(b"y\n").unwrap();
    let mut said = String::new();
    stderr.read_to_string(&mut said).unwrap();
    let refused = repair.wait_with_output().unwrap();
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert_eq!(
        said,
        format!(
            "pqkey: repairing the credential store failed: {shown}: it changed after its repair \
             was planned. No file of the store is lost: each is still in the store or kept in \
             {shown}/damaged; run `pqkey repair` again\n",
            shown = dir.display()
        )
    );
    assert_eq!(files(dir), before, "nothing changed");
    assert!(!dir.join("damaged").exists());
    let again = run(dir, &["repair", "--yes"], "");
    assert_eq!(again.status.code(), Some(0), "{again:?}");
    assert_eq!(FileStore::inspect_in(dir).unwrap(), []);
    assert_eq!(FileStore::open(dir).unwrap().count().unwrap(), 2);
}

/// The soft and hard core-file limits of process `pid`.
fn core_limits(pid: u32) -> (String, String) {
    let limits = fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .unwrap();
    let fields: Vec<_> = line.split_whitespace().collect();
    (fields[4].to_owned(), fields[5].to_owned())
}

/// Run `child`, whose credential key is the FIFO `fifo`, until it exits.
/// When it first opens the FIFO to read its key, note its core-file
/// limits, put the key in a file of its own in the FIFO's place, for every
/// later read, and give the child the key through the FIFO it opened.
fn first_key_read(mut child: Child, fifo: &Path, key: &[u8]) -> (Output, (String, String)) {
    let limits = loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("pqkey exited ({status}) before it read its key");
        }
        // Opening a FIFO to write, without blocking, works only once a
        // reader has it open: the child, reading its key.
        match fs::OpenOptions::new()
            .write(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(fifo)
        {
            Ok(mut writer) => {
                let limits = core_limits(child.id());
                let file = fifo.with_extension("file");
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&file)
                    .unwrap()
                    .write_all(key)
                    .unwrap();
                fs::rename(&file, fifo).unwrap();
                writer.write_all(key).unwrap();
                break limits;
            }
            Err(err) if err.raw_os_error() == Some(nix::libc::ENXIO) => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => panic!("{err}"),
        }
    };
    (child.wait_with_output().unwrap(), limits)
}

/// `pqkey status` and `pqkey repair` decrypt every credential, so they turn
/// core files off, as the key does, before they first read the credential
/// key: here a FIFO, at whose first read the process's core-file limits are
/// already 0, although it started with a limit that allowed core files.
#[test]
fn status_and_repair_turn_core_files_off_before_they_read_a_key() {
    let (_, hard) = getrlimit(Resource::RLIMIT_CORE).unwrap();
    assert!(
        hard > 0,
        "the hard core-file limit is 0, so this test cannot tell whether pqkey turns core files off"
    );
    // The child inherits a limit that allows core files.
    setrlimit(Resource::RLIMIT_CORE, hard.min(1 << 20), hard).unwrap();
    for args in [&["status"][..], &["repair", "--yes"]] {
        let state = State::new(&format!("core-{}", args[0]));
        let dir = &state.0;
        damaged(dir);
        let path = dir.join("keys").join("credential.key");
        let key = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let child = pqkey(dir, args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (output, limits) = first_key_read(child, &path, &key);
        assert_eq!(output.status.code(), Some(0), "{args:?}: {output:?}");
        assert_eq!(limits, ("0".to_owned(), "0".to_owned()), "{args:?}");
        assert_eq!(fs::read(&path).unwrap(), key);
        if args[0] == "status" {
            assert!(
                text(&output.stdout).contains("the credential store is damaged"),
                "{output:?}"
            );
        } else {
            assert_eq!(FileStore::inspect_in(dir).unwrap(), []);
            assert_eq!(FileStore::open(dir).unwrap().count().unwrap(), 3);
        }
    }
}
