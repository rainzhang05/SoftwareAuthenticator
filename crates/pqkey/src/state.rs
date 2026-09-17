//! The state directory, and the CLI's operations on the stored state.
//!
//! The daemon keeps everything in an [`pqkey_ctap::store::FileStore`] in
//! the state directory. The `pin` and `reset` commands work on that same
//! store, and check PINs with the CTAP engine's own retry state machine
//! ([`PinRetryState`]), so a PIN set here is the PIN the authenticator asks
//! for and a retry spent here is a retry the authenticator no longer has.
//!
//! Every function that writes expects the caller to hold the directory's
//! [`StateLock`](crate::state_lock::StateLock); [`pin_info`] only reads, and
//! is safe without it (see its documentation).

use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use pqkey_ctap::ctap::constants::{
    CTAP2_ERR_PIN_AUTH_BLOCKED, CTAP2_ERR_PIN_BLOCKED, CTAP2_ERR_PIN_NOT_SET,
};
use pqkey_ctap::ctap::{PersistentPinState, PinRetryState};
use pqkey_ctap::store::{CredentialStore, FileStore, PinStateRecord};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The name of the default state directory.
const STATE_DIR_NAME: &str = "pqkey";

/// The name the default state directory had before the project was renamed
/// to pqkey. Nothing reads that directory any more.
const LEGACY_STATE_DIR_NAME: &str = "feitian-mldsa-authenticator";

/// `name` in the user's data directory: `$XDG_DATA_HOME/name`, or
/// `~/.local/share/name` when XDG_DATA_HOME is unset.
fn data_dir(name: &str) -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(dir).join(name)
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".local/share").join(name)
    } else {
        PathBuf::from(".").join(name)
    }
}

/// Where the state lives unless `--state-dir` says otherwise.
pub fn default_state_dir() -> PathBuf {
    data_dir(STATE_DIR_NAME)
}

/// A one-line note for someone about to use the default state directory for
/// the first time while the default state directory from before the rename
/// is still there. Its state is not migrated.
pub fn unused_legacy_state_dir_notice(state_dir: &Path) -> Option<String> {
    legacy_state_dir_notice(
        state_dir,
        &default_state_dir(),
        &data_dir(LEGACY_STATE_DIR_NAME),
    )
}

fn legacy_state_dir_notice(state_dir: &Path, default: &Path, legacy: &Path) -> Option<String> {
    (state_dir == default && !state_dir.exists() && legacy.is_dir()).then(|| {
        format!(
            "note: {} is no longer used and can be deleted; pqkey keeps its state in {}",
            legacy.display(),
            state_dir.display()
        )
    })
}

/// Create the state directory if needed and make it private to this user.
pub fn ensure_state_dir(path: &Path) -> io::Result<()> {
    if path.exists() {
        if !path.is_dir() {
            return Err(io::Error::other("state path exists but is not a directory"));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

/// Files of the state format used before the [`FileStore`]: littlefs images
/// encrypted with a keystream that never changed its nonce, and the seed that
/// keystream came from. Nothing reads them any more.
pub const LEGACY_STATE_FILES: [&str; 4] = [
    "master.seed",
    "internal.lfs2",
    "external.lfs2",
    "volatile.lfs2",
];

/// Delete the legacy state files in `state_dir`, returning the names of those
/// that existed. Requires the state lock.
///
/// The old encryption reused its keystream, so these files expose the
/// credentials they hold; they are removed rather than migrated.
pub fn remove_legacy_state(state_dir: &Path) -> io::Result<Vec<&'static str>> {
    let mut removed = Vec::new();
    for name in LEGACY_STATE_FILES {
        match fs::remove_file(state_dir.join(name)) {
            Ok(()) => removed.push(name),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(io::Error::new(
                    err.kind(),
                    format!("cannot remove the legacy state file {name}: {err}"),
                ))
            }
        }
    }
    Ok(removed)
}

/// Remove the legacy state files and log it, once, if there were any.
pub fn remove_and_log_legacy_state(state_dir: &Path) -> io::Result<()> {
    let removed = remove_legacy_state(state_dir)?;
    if !removed.is_empty() {
        log::warn!(
            "removed state from an earlier version ({}); credentials and the PIN stored there are gone",
            removed.join(", ")
        );
    }
    Ok(())
}

/// Minimum PIN length in Unicode code points (CTAP 2.1 section 6.5.1).
pub const MIN_PIN_CODE_POINTS: usize = 4;
/// Maximum PIN length in bytes of UTF-8 (CTAP 2.1 section 6.5.1).
pub const MAX_PIN_BYTES: usize = 63;

/// Check a new PIN against the CTAP 2.1 composition rules: at least
/// [`MIN_PIN_CODE_POINTS`] code points, at most [`MAX_PIN_BYTES`] bytes, and no
/// trailing NUL (CTAP pads PINs with NUL bytes, so a platform could never send
/// such a PIN).
pub fn validate_pin(pin: &str) -> io::Result<()> {
    if pin.chars().count() < MIN_PIN_CODE_POINTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("PIN must be at least {MIN_PIN_CODE_POINTS} characters long"),
        ));
    }
    if pin.len() > MAX_PIN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("PIN must be at most {MAX_PIN_BYTES} bytes long in UTF-8"),
        ));
    }
    if pin.ends_with('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PIN must not end with a NUL character",
        ));
    }
    Ok(())
}

/// CurrentStoredPIN for `pin`: `LEFT(SHA-256(pin), 16)`, as the engine stores
/// it.
fn hash_pin(pin: &str) -> Zeroizing<[u8; 16]> {
    let digest = Zeroizing::new(Sha256::digest(pin.as_bytes()));
    let mut hash = Zeroizing::new([0u8; 16]);
    hash.copy_from_slice(&digest[..16]);
    hash
}

fn store_error(err: pqkey_ctap::store::StoreError) -> io::Error {
    io::Error::other(err)
}

fn open_store(state_dir: &Path) -> io::Result<FileStore> {
    FileStore::open(state_dir).map_err(store_error)
}

/// The PIN state as the engine sees it at power-up. A stored PIN state that
/// cannot be read is an error, so nothing is ever compared against it.
fn load_pin_state(store: &FileStore) -> io::Result<PinRetryState> {
    let record = store
        .pin_state()
        .map_err(|err| io::Error::other(format!("the stored PIN state cannot be read: {err}")))?
        .unwrap_or_default();
    Ok(PinRetryState::power_up(PersistentPinState {
        pin_hash: record.pin_hash,
        pin_retries: record.pin_retries,
    }))
}

/// Write the persistent part of `state`, exactly as the engine does.
fn save_pin_state(store: &mut FileStore, state: &PinRetryState) -> io::Result<()> {
    let persistent = state.persistent();
    let record = PinStateRecord {
        pin_hash: persistent.pin_hash,
        pin_retries: persistent.pin_retries,
        ..PinStateRecord::default()
    };
    store
        .set_pin_state(&record)
        .map_err(|err| io::Error::other(format!("cannot save the PIN state: {err}")))
}

/// Summary view of the persistent PIN state for the `pin status` CLI.
pub struct PinInfo {
    pub is_set: bool,
    pub retries: u8,
    pub blocked: bool,
}

/// Read the persistent PIN summary.
///
/// This only reads, so it does not need the state lock and works while the
/// daemon runs. The store replaces files atomically and re-reads its keys on
/// every operation, so a concurrent PIN change shows either the old or the new
/// state; a concurrent reset can at worst make this fail, never show a
/// mixture. What it cannot see is the daemon's volatile lockout after three
/// consecutive wrong PINs, which lasts until the daemon restarts.
///
/// Opening the store creates its directories and root keys if they do not
/// exist yet; the store makes that safe against a concurrent daemon start.
pub fn pin_info(state_dir: &Path) -> io::Result<PinInfo> {
    let store = open_store(state_dir)?;
    let state = load_pin_state(&store)?;
    Ok(PinInfo {
        is_set: state.is_set(),
        retries: state.retries(),
        blocked: state.retries() == 0,
    })
}

/// Set a PIN on an authenticator that has none. Requires the state lock.
pub fn pin_set(state_dir: &Path, new_pin: &str) -> io::Result<()> {
    validate_pin(new_pin)?;
    let mut store = open_store(state_dir)?;
    let mut state = load_pin_state(&store)?;
    if state.is_set() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a PIN is already set; use 'pin change' instead",
        ));
    }
    state.set_pin(*hash_pin(new_pin));
    save_pin_state(&mut store, &state)
}

/// Replace the PIN after verifying the current one. Requires the state lock.
pub fn pin_change(state_dir: &Path, current_pin: &str, new_pin: &str) -> io::Result<()> {
    validate_pin(new_pin)?;
    let mut store = open_store(state_dir)?;
    let mut state = load_pin_state(&store)?;
    verify_current_pin(&mut store, &mut state, current_pin)?;
    state.set_pin(*hash_pin(new_pin));
    save_pin_state(&mut store, &state)
}

/// Remove the PIN after verifying the current one. Requires the state lock.
///
/// CTAP has no command for this; the result is the PIN state of a reset
/// authenticator, with the credentials kept.
pub fn pin_remove(state_dir: &Path, current_pin: &str) -> io::Result<()> {
    let mut store = open_store(state_dir)?;
    let mut state = load_pin_state(&store)?;
    verify_current_pin(&mut store, &mut state, current_pin)?;
    save_pin_state(&mut store, &PinRetryState::default())
}

/// Factory reset: delete every credential and the PIN, replacing the key that
/// protected them, and remove any legacy state. The attestation key is kept.
/// Returns the legacy state files that were removed. Requires the state lock.
pub fn reset_state(state_dir: &Path) -> io::Result<Vec<&'static str>> {
    let removed = remove_legacy_state(state_dir)?;
    let mut store = open_store(state_dir)?;
    store.clear().map_err(store_error)?;
    Ok(removed)
}

/// Check `candidate` against the stored PIN with the engine's state machine,
/// spending one retry.
///
/// The spent retry is written to disk before the comparison, so an attempt
/// always counts even if the process is killed before it reports the result;
/// if that write fails, the PIN is not compared at all. On success the retry
/// counter is back at its maximum and has been saved.
fn verify_current_pin(
    store: &mut FileStore,
    state: &mut PinRetryState,
    candidate: &str,
) -> io::Result<()> {
    state.check_attempt_allowed().map_err(pin_status_error)?;
    // Every PIN the engine or this CLI ever stored passed these rules, so a
    // candidate that does not cannot match. Reject it without spending a
    // retry, e.g. when Enter is pressed at the prompt by accident.
    if validate_pin(candidate).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PIN is incorrect (it could never have been set; no retry was used)",
        ));
    }

    let attempt = state.begin_attempt().map_err(pin_status_error)?;
    save_pin_state(store, state)?;
    match state.finish_attempt(attempt, Some(hash_pin(candidate).as_slice())) {
        Ok(()) => save_pin_state(store, state),
        // A mismatch changes nothing persistent beyond the retry saved above.
        Err(CTAP2_ERR_PIN_BLOCKED) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PIN is incorrect; no retries remain and the PIN is now blocked until the authenticator is reset",
        )),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("PIN is incorrect ({} retries remaining)", state.retries()),
        )),
    }
}

/// The error for a PIN check the state machine refuses to start.
fn pin_status_error(status: u8) -> io::Error {
    let message = match status {
        CTAP2_ERR_PIN_NOT_SET => "no PIN is currently set",
        CTAP2_ERR_PIN_BLOCKED => "PIN is blocked until the authenticator is reset",
        CTAP2_ERR_PIN_AUTH_BLOCKED => "PIN checks are blocked until the authenticator restarts",
        _ => "the PIN cannot be checked",
    };
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use pqkey_ctap::store::{AttestationRecord, CredentialRecord, PrivateKeyMaterial};
    use pqkey_ctap::CoseAlg;

    // Test characters by UTF-8 width, so the boundaries below are explicit.
    const TWO_BYTES: &str = "\u{e9}"; // e with acute accent
    const THREE_BYTES: &str = "\u{20ac}"; // euro sign
    const FOUR_BYTES: &str = "\u{1f511}"; // key emoji

    const MAX_RETRIES: u8 = PinStateRecord::MAX_PIN_RETRIES;

    #[test]
    fn test_characters_have_the_expected_utf8_widths() {
        assert_eq!(TWO_BYTES.len(), 2);
        assert_eq!(THREE_BYTES.len(), 3);
        assert_eq!(FOUR_BYTES.len(), 4);
    }

    #[test]
    fn minimum_pin_length_counts_code_points_not_bytes() {
        // Enough bytes, too few code points.
        assert!(validate_pin(&TWO_BYTES.repeat(2)).is_err()); // 4 bytes, 2 code points
        assert!(validate_pin(&THREE_BYTES.repeat(3)).is_err()); // 9 bytes, 3 code points
        assert!(validate_pin(&FOUR_BYTES.repeat(3)).is_err()); // 12 bytes, 3 code points
        assert!(validate_pin("abc").is_err());
        assert!(validate_pin("").is_err());

        // Four code points are enough however they are encoded.
        assert!(validate_pin("abcd").is_ok());
        assert!(validate_pin(&TWO_BYTES.repeat(4)).is_ok());
        assert!(validate_pin(&FOUR_BYTES.repeat(4)).is_ok());
        assert!(validate_pin(&format!("ab{TWO_BYTES}{THREE_BYTES}")).is_ok());
    }

    #[test]
    fn maximum_pin_length_counts_bytes_not_code_points() {
        let at_limit = THREE_BYTES.repeat(21);
        assert_eq!(at_limit.len(), MAX_PIN_BYTES);
        assert!(validate_pin(&at_limit).is_ok());

        let at_limit_mixed = format!("{}{TWO_BYTES}", "a".repeat(61));
        assert_eq!(at_limit_mixed.len(), MAX_PIN_BYTES);
        assert!(validate_pin(&at_limit_mixed).is_ok());

        // 63 code points, but the last one takes the encoding to 64 bytes.
        let over_limit = format!("{}{TWO_BYTES}", "a".repeat(62));
        assert_eq!(over_limit.chars().count(), 63);
        assert!(validate_pin(&over_limit).is_err());

        // Only 16 code points, but 64 bytes.
        assert!(validate_pin(&FOUR_BYTES.repeat(16)).is_err());
    }

    #[test]
    fn pin_must_not_end_with_nul() {
        assert!(validate_pin("1234\u{0}").is_err());
        assert!(validate_pin("12\u{0}34").is_ok());
    }

    const PIN: &str = "1234";
    const WRONG_PIN: &str = "9999";
    const NEW_PIN: &str = "5678";

    /// Read the PIN state back through a freshly opened store, as the daemon
    /// or the next CLI invocation would.
    fn state_on_disk(dir: &Path) -> PinStateRecord {
        FileStore::open(dir)
            .expect("open the store")
            .pin_state()
            .expect("read the PIN state")
            .unwrap_or_default()
    }

    #[test]
    fn a_pin_set_by_the_cli_is_the_one_the_engine_stores() {
        let dir = TempDir::new("pin-set");
        let info = pin_info(dir.path()).unwrap();
        assert!(!info.is_set);
        assert_eq!(info.retries, MAX_RETRIES);
        assert!(!info.blocked);

        pin_set(dir.path(), PIN).unwrap();
        let state = state_on_disk(dir.path());
        // LEFT(SHA-256("1234"), 16)
        let expected: [u8; 16] = Sha256::digest(PIN.as_bytes())[..16].try_into().unwrap();
        assert_eq!(state.pin_hash, Some(expected));
        assert_eq!(state.pin_retries, MAX_RETRIES);
        assert!(pin_info(dir.path()).unwrap().is_set);

        let err = pin_set(dir.path(), NEW_PIN).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn wrong_pin_decrements_the_retry_counter_on_disk() {
        let dir = TempDir::new("pin-retries");
        pin_set(dir.path(), PIN).unwrap();

        let err = pin_change(dir.path(), WRONG_PIN, NEW_PIN).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(state_on_disk(dir.path()).pin_retries, MAX_RETRIES - 1);

        // The next invocation continues from the persisted counter, whichever
        // command it is.
        let err = pin_remove(dir.path(), WRONG_PIN).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let state = state_on_disk(dir.path());
        assert_eq!(state.pin_retries, MAX_RETRIES - 2);
        assert_eq!(state.pin_hash, Some(*hash_pin(PIN)));
    }

    #[test]
    fn a_retry_that_cannot_be_saved_is_not_compared() {
        if nix::unistd::geteuid().is_root() {
            // Directory permissions do not stop root from writing.
            return;
        }
        let dir = TempDir::new("pin-save-fails");
        pin_set(dir.path(), PIN).unwrap();
        let mut store = FileStore::open(dir.path()).unwrap();
        let mut state = load_pin_state(&store).unwrap();

        // The store writes a temporary file next to its target; a read-only
        // directory makes that fail.
        let dir_permissions = |mode| {
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).unwrap();
        };
        dir_permissions(0o500);
        let result = verify_current_pin(&mut store, &mut state, PIN);
        dir_permissions(0o700);

        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("cannot save the PIN state"),
            "{err}"
        );
        // Refused without comparing: the correct PIN did not reset the
        // in-memory counter, and nothing changed on disk.
        assert_eq!(state.retries(), MAX_RETRIES - 1);
        assert_eq!(state_on_disk(dir.path()).pin_retries, MAX_RETRIES);
    }

    #[test]
    fn pin_blocks_when_retries_run_out_and_then_refuses_the_correct_pin() {
        let dir = TempDir::new("pin-block");
        pin_set(dir.path(), PIN).unwrap();
        for _ in 0..MAX_RETRIES {
            let err = pin_change(dir.path(), WRONG_PIN, NEW_PIN).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }

        let info = pin_info(dir.path()).unwrap();
        assert!(info.is_set);
        assert_eq!(info.retries, 0);
        assert!(info.blocked);

        for result in [
            pin_change(dir.path(), PIN, NEW_PIN),
            pin_remove(dir.path(), PIN),
        ] {
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert!(err.to_string().contains("blocked"), "{err}");
        }
        let state = state_on_disk(dir.path());
        assert_eq!(state.pin_hash, Some(*hash_pin(PIN)));
        assert_eq!(state.pin_retries, 0);
    }

    #[test]
    fn correct_pin_resets_the_retry_counter() {
        let dir = TempDir::new("pin-reset-counters");
        pin_set(dir.path(), PIN).unwrap();
        for _ in 0..MAX_RETRIES - 1 {
            pin_change(dir.path(), WRONG_PIN, NEW_PIN).unwrap_err();
        }
        assert_eq!(state_on_disk(dir.path()).pin_retries, 1);

        // The last remaining retry still accepts the correct PIN.
        pin_change(dir.path(), PIN, NEW_PIN).unwrap();
        let state = state_on_disk(dir.path());
        assert_eq!(state.pin_hash, Some(*hash_pin(NEW_PIN)));
        assert_eq!(state.pin_retries, MAX_RETRIES);

        pin_remove(dir.path(), WRONG_PIN).unwrap_err();
        pin_remove(dir.path(), NEW_PIN).unwrap();
        let state = state_on_disk(dir.path());
        assert_eq!(state.pin_hash, None);
        assert_eq!(state.pin_retries, MAX_RETRIES);
    }

    #[test]
    fn rejected_input_does_not_spend_a_retry() {
        let dir = TempDir::new("pin-no-retry");
        pin_set(dir.path(), PIN).unwrap();

        // A current PIN no authenticator could have accepted.
        for impossible in ["", "123", &"1".repeat(MAX_PIN_BYTES + 1)] {
            let err = pin_remove(dir.path(), impossible).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
        // An invalid new PIN is refused before the current PIN is checked.
        let err = pin_change(dir.path(), WRONG_PIN, "12").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        assert_eq!(state_on_disk(dir.path()).pin_retries, MAX_RETRIES);
    }

    #[test]
    fn checking_a_pin_needs_one_to_be_set() {
        let dir = TempDir::new("pin-not-set");
        for result in [
            pin_change(dir.path(), PIN, NEW_PIN),
            pin_remove(dir.path(), PIN),
        ] {
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert!(err.to_string().contains("no PIN"), "{err}");
        }
    }

    #[test]
    fn an_unreadable_pin_state_is_never_compared_or_overwritten() {
        let dir = TempDir::new("pin-corrupt");
        pin_set(dir.path(), PIN).unwrap();
        let path = dir.path().join("pin-state");
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, &bytes).unwrap();

        for result in [
            pin_change(dir.path(), PIN, NEW_PIN).map(drop),
            pin_remove(dir.path(), PIN).map(drop),
            pin_set(dir.path(), NEW_PIN).map(drop),
            pin_info(dir.path()).map(drop),
        ] {
            let err = result.unwrap_err();
            assert!(err.to_string().contains("cannot be read"), "{err}");
        }
        assert_eq!(fs::read(&path).unwrap(), bytes);

        // A reset is the way out.
        reset_state(dir.path()).unwrap();
        assert!(!pin_info(dir.path()).unwrap().is_set);
    }

    fn credential(id: u8) -> CredentialRecord {
        CredentialRecord {
            credential_id: vec![id; 16],
            rp_id: "example.com".into(),
            user_id: vec![id],
            user_name: None,
            user_display_name: None,
            alg: CoseAlg::ES256,
            private_key: PrivateKeyMaterial::generate(CoseAlg::ES256),
            cred_random_with_uv: [1; 32],
            cred_random_without_uv: [2; 32],
            cred_protect: 1,
            sign_count: 0,
            created_at: 0,
        }
    }

    #[test]
    fn reset_clears_credentials_and_the_pin_and_keeps_attestation() {
        let dir = TempDir::new("reset");
        pin_set(dir.path(), PIN).unwrap();
        pin_change(dir.path(), WRONG_PIN, NEW_PIN).unwrap_err();
        let attestation = AttestationRecord {
            private_key: {
                let mut key = [0u8; 32];
                key[31] = 7;
                key
            },
            certificate_chain: vec![vec![0x30, 0x00]],
        };
        {
            let mut store = FileStore::open(dir.path()).unwrap();
            store.put(&credential(1)).unwrap();
            store.put(&credential(2)).unwrap();
            store.set_attestation(&attestation).unwrap();
        }
        let old_key = fs::read(dir.path().join("keys/credential.key")).unwrap();

        reset_state(dir.path()).unwrap();

        let store = FileStore::open(dir.path()).unwrap();
        assert_eq!(store.count().unwrap(), 0);
        let state = store
            .pin_state()
            .unwrap()
            .expect("reset writes a PIN state");
        assert_eq!(state.pin_hash, None);
        assert_eq!(state.pin_retries, MAX_RETRIES);
        assert_eq!(
            store.attestation().unwrap().unwrap().certificate_chain,
            attestation.certificate_chain
        );
        let new_key = fs::read(dir.path().join("keys/credential.key")).unwrap();
        assert_ne!(old_key, new_key, "reset must replace the credential key");

        // A PIN can be set again afterwards.
        pin_set(dir.path(), NEW_PIN).unwrap();
    }

    #[test]
    fn legacy_state_files_are_removed_and_nothing_else() {
        let dir = TempDir::new("legacy");
        for name in LEGACY_STATE_FILES {
            fs::write(dir.path().join(name), b"old").unwrap();
        }
        pin_set(dir.path(), PIN).unwrap();
        fs::write(dir.path().join("authenticator.log"), b"log").unwrap();

        let mut removed = remove_legacy_state(dir.path()).unwrap();
        removed.sort_unstable();
        let mut expected = LEGACY_STATE_FILES.to_vec();
        expected.sort_unstable();
        assert_eq!(removed, expected);
        for name in LEGACY_STATE_FILES {
            assert!(!dir.path().join(name).exists(), "{name}");
        }
        // The current store and other files are untouched.
        assert!(dir.path().join("authenticator.log").exists());
        assert!(pin_info(dir.path()).unwrap().is_set);

        // Nothing left to remove.
        assert!(remove_legacy_state(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn the_default_state_dir_is_named_pqkey() {
        assert_eq!(default_state_dir().file_name().unwrap(), "pqkey");
    }

    #[test]
    fn the_old_default_state_dir_is_pointed_out_once() {
        let dir = TempDir::new("legacy-dir");
        let default = dir.path().join("pqkey");
        let legacy = dir.path().join("feitian-mldsa-authenticator");

        // No old directory: nothing to say.
        assert_eq!(legacy_state_dir_notice(&default, &default, &legacy), None);

        fs::create_dir(&legacy).unwrap();
        let notice = legacy_state_dir_notice(&default, &default, &legacy).unwrap();
        assert!(!notice.contains('\n'), "{notice}");
        assert!(notice.contains(&*legacy.to_string_lossy()), "{notice}");
        assert!(notice.contains("can be deleted"), "{notice}");

        // Only for the default state directory.
        let other = dir.path().join("elsewhere");
        assert_eq!(legacy_state_dir_notice(&other, &default, &legacy), None);

        // Once the new directory exists it has been said.
        fs::create_dir(&default).unwrap();
        assert_eq!(legacy_state_dir_notice(&default, &default, &legacy), None);
    }

    #[test]
    fn reset_removes_legacy_state_files() {
        let dir = TempDir::new("reset-legacy");
        fs::write(dir.path().join("master.seed"), [0u8; 32]).unwrap();
        fs::write(dir.path().join("internal.lfs2"), [0u8; 256]).unwrap();

        let mut removed = reset_state(dir.path()).unwrap();
        removed.sort_unstable();
        assert_eq!(removed, ["internal.lfs2", "master.seed"]);
        assert!(!dir.path().join("master.seed").exists());
        assert!(!dir.path().join("internal.lfs2").exists());
    }
}
