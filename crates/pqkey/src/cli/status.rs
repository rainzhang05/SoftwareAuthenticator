//! `pqkey status`, and the checks of the running key that `pqkey setup`
//! shares: [`running_problems`] and [`presence_warning`].

use std::{io, path::Path, time::Duration};

use pqkey_ctap::store::{
    Damage, DirectoryFlush, FileStore, StoreError, damage_fix, damage_summary, damage_unchecked,
};

use super::checks::{FREE_SPACE, MAKE_WRITABLE, Problem};
use super::daemon::{self, Running};
use super::daemon_info::DaemonInfo;
use super::key::{REPLUG, STATUS_WAIT, client_error, open_node};
use super::output::{self, outln};
use crate::client::ctap2::{Authenticator, ClientError, Info, PinRetries};
use crate::platform::{self, System, UserService};
use crate::presence::notification::{ConnectError, NotificationServer, ServerInfo};
use crate::state::{Room, default_state_dir};

/// `pqkey status`: whether the key runs, its device, PIN and room for
/// passkeys, then every problem found, with its fix.
pub fn status(state_dir: &Path) -> io::Result<()> {
    let system = System::real()?;
    let mut problems = Vec::new();
    let running = match daemon::running(state_dir) {
        Err(err) if err.kind() == io::ErrorKind::ResourceBusy => {
            return outln!("Key:      starting or stopping");
        }
        // A state directory that cannot be looked into for the key's lock and
        // pid: the problem, which status cannot list without the key's state.
        Err(err) => {
            let problem = unchecked_state_dir(state_dir, &err, false);
            return Err(io::Error::new(
                err.kind(),
                format!("{}; {}", problem.what, problem.fix),
            ));
        }
        Ok(running) => running,
    };
    // Checking the credential store decrypts every credential and the PIN
    // state: keep them out of core files, and this process out of reach, as
    // the daemon does.  The PIN line says whether the PIN state is damaged.
    platform::disable_core_dumps()?;
    let inspected = FileStore::inspect_in(state_dir);
    match running {
        None => {
            outln!("Key:      not running; `pqkey start` starts it")?;
            problems.extend(system.start_problems()?);
            // `pqkey start` asks with notifications on the default state
            // directory; test rigs choose for themselves.
            if state_dir == default_state_dir() {
                problems.extend(system.notification_problem(&notification_server())?);
            }
        }
        Some(running) => {
            // Read once, and before the device wait: a read after a restart
            // fails as if an older pqkey had started the key. One that fails
            // because the key no longer runs as found means it is starting or
            // stopping.
            let info = super::daemon_info_of(state_dir, running.pid());
            if info.is_err()
                && crate::state_lock::daemon_state(state_dir)?
                    != crate::state_lock::DaemonState::Running(running.pid())
            {
                return outln!("Key:      starting or stopping");
            }
            match running {
                Running::Service(pid) => outln!(
                    "Key:      running (pid {pid}, {})",
                    UserService::DESCRIPTION
                )?,
                Running::Daemon(pid) => outln!("Key:      running (pid {pid})")?,
            }
            show_key(running, inspected.as_deref().unwrap_or_default())?;
            let info = info?;
            problems.extend(running_problems_of(&system, running, &info, STATUS_WAIT)?);
            problems.extend(presence_problem(&info.1, running));
        }
    }
    problems.extend(state_dir_problem(state_dir, running.is_some()));
    problems.extend(store_problem(state_dir, inspected));
    problems.extend(service_problems(state_dir, running)?);
    if !problems.is_empty() {
        outln!()?;
        output::problems(&problems)?;
    }
    Ok(())
}

/// The lines of `status` about the running key itself, whose credential
/// store was found to have `damage`.
fn show_key(running: Running, damage: &[Damage]) -> io::Result<()> {
    let Ok((path, link)) = open_node(running, STATUS_WAIT) else {
        return outln!("Device:   cannot be opened (see below)");
    };
    let mut key = match Authenticator::open_within(link, STATUS_WAIT) {
        Ok(key) => key,
        Err(ClientError::Hid(crate::client::ctaphid::HidError::Busy)) => {
            return outln!(
                "Device:   {}, busy with another program's request (a browser waiting for your \
                 approval?)",
                path
            );
        }
        Err(err) => return outln!("Device:   {}, not answering: {err}", path),
    };
    outln!("Device:   {}", path)?;
    let info = key.info().map_err(client_error)?;
    match info.pin_set {
        Some(true) => {
            let retries = key.pin_retries().map_err(client_error)?;
            outln!("PIN:      {}", pin_state(retries, damage))?;
        }
        Some(false) => {
            outln!("PIN:      not set; `pqkey pin` sets one (Chromium asks for one)")?;
        }
        None => outln!("PIN:      not supported")?,
    }
    for line in policy_status(&info) {
        outln!("{line}")?;
    }
    outln!("{}", passkeys_status(&info))
}

/// The passkeys line of `status`: the room for more, which the key leaves
/// out when it cannot count its passkeys, as where its credential store is
/// damaged.
fn passkeys_status(info: &Info) -> String {
    match info.remaining_discoverable {
        Some(remaining) => format!("Passkeys: room for {remaining} more"),
        None => "Passkeys: cannot be counted".to_owned(),
    }
}

pub(super) fn policy_status(info: &Info) -> Vec<&'static str> {
    let mut lines = Vec::new();
    if info.always_uv == Some(true) {
        lines.push("Always UV: on; registrations and sign-ins require the PIN");
    }
    if info.force_pin_change == Some(true) {
        lines.push("PIN change required; run `pqkey pin`");
    }
    lines
}

/// What keeps browsers from using the key `running`, waiting up to `wait`
/// for its device: one they cannot open, or notifications that cannot ask.
pub fn running_problems(
    state_dir: &Path,
    system: &System,
    running: Running,
    wait: Duration,
) -> io::Result<Vec<Problem>> {
    let info = super::daemon_info_of(state_dir, running.pid())?;
    running_problems_of(system, running, &info, wait)
}

/// [`running_problems`] of the key `running`, whose published information and
/// options are `info`. Notifications are checked on the key's own session bus
/// (`System::key_notification_problem`).
fn running_problems_of(
    system: &System,
    running: Running,
    (info, args): &(DaemonInfo, super::DaemonArgs),
    wait: Duration,
) -> io::Result<Vec<Problem>> {
    let mut problems = system.device_problems(running.pid(), wait)?;
    match args.presence {
        super::PresenceArg::Notify => {
            problems.extend(system.key_notification_problem(info.session_bus_address().as_deref())?)
        }
        // Setup does not restart a running key for a changed drop-in: the
        // key is stopped first, as for --presence auto-approve. A key started
        // by hand has the option from its own command line; the service then
        // has nothing to change unless its ExecStart= has it too.
        super::PresenceArg::Unanswered => problems.push(Problem::new(
            "the configured presence provider never answers requests",
            "configure the service to use --presence notify where `systemctl --user cat pqkey` \
             shows --presence unanswered, then run `pqkey stop && pqkey setup`",
        )),
        // Nothing keeps browsers from using it; `presence_warning` names it.
        super::PresenceArg::AutoApprove => {}
    }
    Ok(problems)
}

/// A key `running` that approves every request without asking, as `--presence
/// auto-approve` makes it, and how to make it ask: a problem for `status`, and
/// a warning for `setup`, which does not fail on it. Setup installs no such
/// option, so the service has it from ExecStart= in its unit or a drop-in, and
/// the fix removes only the option.
pub fn presence_warning(state_dir: &Path, running: Running) -> io::Result<Option<Problem>> {
    Ok(presence_problem(
        &super::daemon_args_of(state_dir, running.pid())?,
        running,
    ))
}

/// [`presence_warning`] of the key `running` with the options `args`.
fn presence_problem(args: &super::DaemonArgs, running: Running) -> Option<Problem> {
    if args.presence != super::PresenceArg::AutoApprove {
        return None;
    }
    Some(Problem::new(
        "the key runs with --presence auto-approve: it approves every registration, sign-in and \
         reset without asking, so anything running as you can use your passkeys unnoticed",
        match running {
            Running::Service(_) => {
                "remove --presence auto-approve from the ExecStart= line that `systemctl --user \
                 cat pqkey` shows, in the unit or drop-in file named above it, then run `pqkey \
                 stop && pqkey setup`"
            }
            Running::Daemon(_) => {
                "run `pqkey stop`, then `pqkey start` without --presence auto-approve"
            }
        },
    ))
}

/// The room the key needs on the filesystem of its state directory, in bytes.
/// Its largest write is a registration in a store of the earlier layout
/// ([`FileStore`]): the format marker, the records directory, the credential
/// record and the list of credentials, at most 33,054 bytes for the 1,000 the
/// key holds; 12 blocks of 4 KiB, or 4 of 64 KiB, which is 256 KiB. 1 MiB,
/// the most any one file of the store may take, leaves room to spare.
const ROOM_BYTES: u64 = 1 << 20;
/// The files and directories that write creates.
const ROOM_FILES: u64 = 4;

/// Where the key writes, which a full or read-only state filesystem stops.
const WRITES: &str =
    "but the key writes there as it starts and with every registration, sign-in and PIN entry";

/// What keeps the key from using the filesystem of its state directory:
/// [`state_fs_problem`] of what statvfs(3) says of it or, failing that, a
/// filesystem that does not support flushing directories, where the key
/// refuses to set or check a PIN and cannot save passkeys, or a flush that
/// fails. It writes and creates nothing; the flush, of a directory that
/// exists, changes nothing. A fix starts the key that is not `running`.
fn state_dir_problem(state_dir: &Path, running: bool) -> Option<Problem> {
    if let Some(problem) = state_fs_problem(state_dir, crate::state::room(state_dir), running) {
        return Some(problem);
    }
    let err = match FileStore::directory_flush_in(state_dir) {
        DirectoryFlush::Supported => return None,
        DirectoryFlush::Unsupported(err) => err,
        DirectoryFlush::Failed(err) => {
            return match &err {
                // A state directory the key has not created yet.
                StoreError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound => None,
                StoreError::Io { source, .. } => {
                    Some(unchecked_state_dir(state_dir, source, running))
                }
                err => Some(unchecked_state_dir(state_dir, err, running)),
            };
        }
    };
    Some(Problem::new(
        format!(
            "the key cannot use a PIN or save passkeys in its state directory, which cannot be \
             flushed ({err}): it refuses to set or check a PIN there"
        ),
        format!(
            "run `pqkey stop`, move {} to a local filesystem (or copy it and verify the copy \
             before deleting the original), leave a symbolic link in its place, then run `pqkey \
             start`, which checks again; until then use the key only as a security key, without \
             a PIN",
            state_dir.display()
        ),
    ))
}

/// The problem with a state directory whose filesystem has `room`: one that
/// is read-only, or full, with less room than the key's largest write
/// ([`ROOM_BYTES`], [`ROOM_FILES`]), or one that cannot be checked. A size the
/// filesystem does not report is none. A fix starts the key that is not
/// `running`.
fn state_fs_problem(state_dir: &Path, room: io::Result<Room>, running: bool) -> Option<Problem> {
    let room = match room {
        Ok(room) => room,
        Err(err) => return Some(unchecked_state_dir(state_dir, &err, running)),
    };
    let dir = state_dir.display();
    let start = then_start(running);
    if room.read_only {
        return Some(Problem::new(
            format!("the state directory {dir} is on a read-only filesystem, {WRITES}"),
            format!("{MAKE_WRITABLE}{start}"),
        ));
    }
    let bytes = room.bytes.filter(|&bytes| bytes < ROOM_BYTES).map(|bytes| {
        if bytes < 1024 {
            format!("{bytes} B left")
        } else {
            format!("{} KiB left", bytes / 1024)
        }
    });
    let files = room
        .files
        .filter(|&files| files < ROOM_FILES)
        .map(|files| match files {
            1 => "room for 1 more file".to_owned(),
            _ => format!("room for {files} more files"),
        });
    let left: Vec<String> = bytes.into_iter().chain(files).collect();
    if left.is_empty() {
        return None;
    }
    Some(Problem::new(
        format!(
            "the state directory {dir} is on a full filesystem ({}), {WRITES}",
            left.join(", ")
        ),
        format!("{FREE_SPACE}{start}"),
    ))
}

/// A state directory that `status` cannot check, with `err`. A fix starts
/// the key that is not `running`.
fn unchecked_state_dir(state_dir: &Path, err: &dyn std::fmt::Display, running: bool) -> Problem {
    Problem::new(
        format!(
            "the state directory {} cannot be checked ({err}), and the key may not be able to \
             use it either",
            state_dir.display()
        ),
        format!(
            "check that it is a directory of yours that you can read, under directories you can \
             enter (`ls -ld` shows each one's owner and mode), and look in `journalctl -k` for \
             disk errors{}",
            then_start(running)
        ),
    )
}

/// The end of a fix that the key needs started again, unless it is `running`.
fn then_start(running: bool) -> &'static str {
    if running {
        ""
    } else {
        ", then run `pqkey start`"
    }
}

/// A credential store in `state_dir` that `inspected` found damaged, with
/// what fails, or that it could not check, and what to do: what the key logs
/// as it starts (`service::log_if_store_damaged`). The store is read as it
/// is, while the key may change it ([`FileStore::inspect`]).
fn store_problem(state_dir: &Path, inspected: Result<Vec<Damage>, StoreError>) -> Option<Problem> {
    let dir = state_dir.display().to_string();
    match inspected {
        Ok(damage) if damage.is_empty() => None,
        Ok(damage) => Some(Problem::new(
            damage_summary(&damage),
            damage_fix(&damage, &dir),
        )),
        Err(err) => Some(Problem::new(damage_unchecked(&err), damage_fix(&[], &dir))),
    }
}

/// What the notification server on this process's own session bus says about
/// itself.
fn notification_server() -> Result<ServerInfo, ConnectError> {
    let mut bus = platform::notifications().map_err(|err| ConnectError::Failed(err.to_string()))?;
    let server = bus.connect();
    bus.disconnect();
    server
}

/// Whether the installed user service runs the key on the default state
/// directory, as `pqkey setup` arranges, and starts it with the session, with
/// the unit setup installs.
fn service_problems(state_dir: &Path, running: Option<Running>) -> io::Result<Vec<Problem>> {
    if state_dir != default_state_dir() {
        return Ok(Vec::new());
    }
    let mut problems = UserService::problems(running.is_some())?;
    problems.extend(UserService::kept_unit());
    if let Some(Running::Daemon(pid)) = running
        && daemon::uses_service(state_dir)?
    {
        problems.push(UserService::manual_start_problem(pid)?);
    }
    Ok(problems)
}

/// The PIN line of `status`, for a credential store found to have `damage`.
/// A PIN blocked by a damaged PIN state is said to be, with the fix that
/// keeps the passkeys, which `status` lists below.  For any other blocked PIN
/// it says to restart the key first, which clears a block that came from a
/// PIN state the key could not read, and only then to reset it, which erases
/// the passkeys.
pub(super) fn pin_state(retries: PinRetries, damage: &[Damage]) -> String {
    if retries.retries == 0 && damage.iter().any(Damage::is_pin_state) {
        "blocked, because pin-state is damaged: move it out of the state directory and set a new \
         PIN, as the fix below says, which keeps every passkey"
            .to_owned()
    } else if retries.retries == 0 {
        format!(
            "blocked; restart the key ({REPLUG}) and run `pqkey status` again: if it is still \
             blocked, only `pqkey reset` makes the key usable again, and it erases every passkey \
             and large blob"
        )
    } else if retries.power_cycle_needed {
        format!("set; locked after 3 wrong PINs in a row until re-plugged: {REPLUG}")
    } else {
        format!("set ({} retries left)", retries.retries)
    }
}

#[cfg(test)]
mod tests {
    use pqkey_ctap::CoseAlg;
    use pqkey_ctap::ctap::constants::{CTAP2_ERR_PIN_BLOCKED, CTAP2_ERR_PROCESSING};
    use pqkey_ctap::store::{CredentialStore, PinStateRecord};

    use super::*;
    use crate::cli::output::errln;
    use crate::client::tests::{discoverable, start};
    use crate::test_support::{
        TempDir, assert_names, assert_problem, assert_ran, child_test, listed,
    };

    /// `status` reports a state directory whose filesystem refuses to flush
    /// directories, as procfs does with EINVAL, with its fix; nothing for one
    /// that flushes, or that does not exist yet.
    #[test]
    fn status_reports_a_state_directory_that_cannot_keep_a_pin() {
        let dir = TempDir::new("status-flush");
        assert_eq!(state_dir_problem(dir.path(), false), None);
        assert_eq!(state_dir_problem(&dir.path().join("missing"), false), None);
        let problem =
            state_dir_problem(Path::new("/proc"), false).expect("procfs cannot be flushed");
        assert!(problem.what.contains("cannot use a PIN"), "{problem:?}");
        assert!(problem.what.contains("(/proc: "), "{problem:?}");
        // The key is stopped before its directory moves, and started after.
        let at = |text: &str| {
            problem
                .fix
                .find(text)
                .unwrap_or_else(|| panic!("{problem:?}"))
        };
        assert!(at("run `pqkey stop`") < at("move /proc to a local filesystem"));
        assert!(at("move /proc to a local filesystem") < at("run `pqkey start`"));
        assert!(problem.fix.contains("verify the copy"), "{problem:?}");
        assert!(problem.fix.contains("without a PIN"), "{problem:?}");
    }

    /// `status` names a state directory on a full filesystem, one with less
    /// room than the key's largest write in bytes or in files, and on a
    /// read-only one, whatever its room, with the fix, which starts a key
    /// that does not run; and one it cannot check, with the error. Room
    /// enough, or a size the filesystem does not report, is no problem.
    #[test]
    fn status_names_a_full_or_read_only_state_filesystem_with_its_fix() {
        let dir = Path::new("/home/u/.local/share/pqkey");
        let room = |bytes, files, read_only| {
            Ok(Room {
                bytes,
                files,
                read_only,
            })
        };
        for (bytes, files) in [
            (Some(ROOM_BYTES), Some(ROOM_FILES)),
            (Some(u64::MAX), Some(u64::MAX)),
            (None, None),
            (None, Some(ROOM_FILES)),
            (Some(ROOM_BYTES), None),
        ] {
            for running in [false, true] {
                assert_eq!(
                    state_fs_problem(dir, room(bytes, files, false), running),
                    None,
                    "{bytes:?} {files:?}"
                );
            }
        }
        // The problem with what `room` returns, whose fix ends with `pqkey
        // start` for a key that does not run, and only for that.
        let named = |room: &dyn Fn() -> io::Result<Room>, cause: &[&str], fix: &[&str]| {
            for running in [false, true] {
                let problem = state_fs_problem(dir, room(), running).expect("a problem");
                let start: &[&str] = if running { &[] } else { &["`pqkey start`"] };
                assert_problem(&problem, cause, &[fix, start].concat());
                assert_eq!(problem.fix.contains("pqkey start"), !running, "{problem:?}");
            }
        };
        let at = "state directory /home/u/.local/share/pqkey";
        for (bytes, files, left) in [
            (Some(0), Some(u64::MAX), "0 B left"),
            (Some(1023), None, "1023 B left"),
            (Some(1024), Some(ROOM_FILES), "1 KiB left"),
            (Some(ROOM_BYTES - 1), None, "1023 KiB left"),
            (
                Some(ROOM_BYTES),
                Some(ROOM_FILES - 1),
                "room for 3 more files",
            ),
            (None, Some(0), "room for 0 more files"),
            (Some(4096), Some(1), "4 KiB left, room for 1 more file"),
        ] {
            named(
                &|| room(bytes, files, false),
                &[at, "full filesystem", &format!("({left})"), "writes there"],
                &["free some space", "`df -h`", "`df -i`"],
            );
        }
        for (bytes, files) in [
            (Some(u64::MAX), Some(u64::MAX)),
            (Some(0), Some(0)),
            (None, None),
        ] {
            named(
                &|| room(bytes, files, true),
                &[at, "read-only filesystem", "writes there"],
                &["remount", "read-write", "`fsck`"],
            );
        }
        let eio = nix::errno::Errno::EIO;
        named(
            &|| Err(io::Error::from(eio)),
            &[at, "cannot be checked", &io::Error::from(eio).to_string()],
            &["`ls -ld`", "`journalctl -k`"],
        );
    }

    /// The problem with a state directory that cannot be checked: under a
    /// file, where statvfs(3) fails, or a socket, which statvfs(3) can check,
    /// but which cannot be opened to be flushed; the fix starts the key.
    /// (`status` itself stops before it lists problems for these two, where
    /// it cannot open the key's lock in them: see `failed_service.rs`.)
    #[test]
    fn status_names_a_state_directory_it_cannot_check() {
        let dir = TempDir::new("status-unchecked");
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        let socket = dir.path().join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        use nix::errno::Errno;
        for (state_dir, err) in [(file.join("pqkey"), Errno::ENOTDIR), (socket, Errno::ENXIO)] {
            let problem = state_dir_problem(&state_dir, false).expect("a problem");
            assert_problem(
                &problem,
                &[
                    &state_dir.display().to_string(),
                    "cannot be checked",
                    &io::Error::from(err).to_string(),
                ],
                &["`ls -ld`", "`journalctl -k`", "`pqkey start`"],
            );
        }
    }

    /// What `status` and `setup` say about a key run with --presence
    /// auto-approve, and the commands of their fixes for the service and for
    /// a key started by hand.
    const AUTO_APPROVE: [&str; 3] = ["--presence auto-approve", "without asking", "unnoticed"];
    const SERVICE_FIX: [&str; 4] = [
        "remove --presence auto-approve",
        "ExecStart=",
        "`systemctl --user cat pqkey`",
        "`pqkey stop && pqkey setup`",
    ];
    const BY_HAND_FIX: [&str; 3] = [
        "`pqkey stop`",
        "`pqkey start`",
        "without --presence auto-approve",
    ];
    /// What `status` says about a key that never answers, and its fix.
    const UNANSWERED: [&str; 2] = ["presence provider", "never answers"];
    const UNANSWERED_FIX: [&str; 4] = [
        "--presence notify",
        "`systemctl --user cat pqkey`",
        "--presence unanswered",
        "`pqkey stop && pqkey setup`",
    ];

    /// Publish this process as the key running on `state_dir` with
    /// `presence`, as a daemon does once it serves. It runs while the
    /// returned lock is held.
    fn run_as_key(
        state_dir: &Path,
        presence: crate::cli::PresenceArg,
    ) -> crate::state_lock::StateLock {
        publish_as_key(state_dir, key_info(presence))
    }

    /// What a key with `presence` publishes, run in this process's
    /// environment.
    fn key_info(presence: crate::cli::PresenceArg) -> DaemonInfo {
        crate::test_support::daemon_info(&crate::cli::DaemonArgs {
            presence,
            ..Default::default()
        })
    }

    /// [`run_as_key`], publishing `info`.
    fn publish_as_key(state_dir: &Path, info: DaemonInfo) -> crate::state_lock::StateLock {
        let lock = crate::state_lock::StateLock::try_acquire(state_dir)
            .unwrap()
            .unwrap();
        info.publish(state_dir, &lock).unwrap();
        crate::state_lock::write_pid_file(state_dir, &lock).unwrap();
        lock
    }

    /// The presence option `name` names.
    fn presence_named(name: &str) -> crate::cli::PresenceArg {
        use crate::cli::PresenceArg;
        [
            PresenceArg::Notify,
            PresenceArg::AutoApprove,
            PresenceArg::Unanswered,
        ]
        .into_iter()
        .find(|presence| presence.name() == name)
        .unwrap()
    }

    /// A directory with a fake `systemctl`, for `PATH`, which says that the
    /// user service is installed and enabled, and that its main process is
    /// its caller's parent where `PQKEY_STATUS_RUNS` is `service`, or that it
    /// has none. Asked for that, it first removes the file
    /// `PQKEY_STATUS_STOPS` names, if any.
    fn fake_systemctl(dir: &Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let systemctl = bin.join("systemctl");
        std::fs::write(
            &systemctl,
            r#"#!/bin/sh
case "$*" in
*LoadState,*) printf 'LoadState=loaded\nUnitFileState=enabled\n' ;;
*LoadState*) echo loaded ;;
*MainPID*)
    [ -z "$PQKEY_STATUS_STOPS" ] || /bin/rm -f "$PQKEY_STATUS_STOPS"
    if [ "$PQKEY_STATUS_RUNS" = service ]; then echo "$PPID"; else echo 0; fi ;;
*) exit 1 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    /// Only a key that approves without asking gets the presence warning,
    /// with the fix for how it runs, and the warning stays out of
    /// `running_problems`, which setup fails on. A key that never answers
    /// keeps its problem. (Notify's problem asks the session bus: see
    /// `status_names_a_key_that_approves_without_asking`.)
    #[test]
    fn only_a_key_that_approves_without_asking_gets_the_presence_warning() {
        use crate::cli::PresenceArg;
        let me = nix::unistd::Pid::this();
        let system = System::real().unwrap();
        for presence in [
            PresenceArg::Notify,
            PresenceArg::AutoApprove,
            PresenceArg::Unanswered,
        ] {
            let dir = TempDir::new("presence-warning");
            let _key = run_as_key(dir.path(), presence);
            let warnings = [Running::Service(me), Running::Daemon(me)]
                .map(|running| presence_warning(dir.path(), running).unwrap());
            let expected = system.device_problems(me, Duration::ZERO).unwrap();
            match presence {
                PresenceArg::Notify => {
                    assert_eq!(warnings, [None, None]);
                    continue;
                }
                PresenceArg::AutoApprove => {
                    let [Some(service), Some(by_hand)] = &warnings else {
                        panic!("{warnings:?}");
                    };
                    assert_problem(service, &AUTO_APPROVE, &SERVICE_FIX);
                    assert_problem(by_hand, &AUTO_APPROVE, &BY_HAND_FIX);
                }
                PresenceArg::Unanswered => assert_eq!(warnings, [None, None]),
            }
            for running in [Running::Service(me), Running::Daemon(me)] {
                let mut found =
                    running_problems(dir.path(), &system, running, Duration::ZERO).unwrap();
                if presence == PresenceArg::Unanswered {
                    let unanswered = found.pop().expect("its problem");
                    assert_problem(&unanswered, &UNANSWERED, &UNANSWERED_FIX);
                }
                assert_eq!(found, expected, "{presence:?}");
            }
        }
    }

    /// Rewrite what the key on `state_dir` published as the header
    /// `pqkey-daemon-VERSION PID DEVICE INODE` gives it, with no session bus:
    /// version `v1` is a pqkey too old to publish its bus.
    fn publish_as_version(state_dir: &Path, version: &str) {
        let path = state_dir.join(crate::state_lock::INFO_FILE);
        let published = std::fs::read(&path).unwrap();
        let end = published.iter().position(|&byte| byte == b'\n').unwrap();
        // pqkey-daemon-v2 PID DEVICE INODE BUS
        let header: Vec<&str> = std::str::from_utf8(&published[..end])
            .unwrap()
            .split(' ')
            .collect();
        let mut rewritten =
            format!("pqkey-daemon-{version} {}", header[1..4].join(" ")).into_bytes();
        rewritten.extend_from_slice(&published[end..]);
        std::fs::write(&path, rewritten).unwrap();
    }

    /// The child of the tests of `status` that play a key: this process
    /// plays a key on the default state directory, run with the presence
    /// `PQKEY_STATUS_CHILD` names, and runs `pqkey status`. The key's
    /// DBUS_SESSION_BUS_ADDRESS is `PQKEY_STATUS_KEY_BUS` where that is set,
    /// with `-` for none, and this process's otherwise. Where
    /// `PQKEY_STATUS_KEY_VERSION` is set, the key publishes that version of
    /// its information instead (`publish_as_version`).
    #[test]
    fn status_child() {
        use std::os::unix::ffi::OsStrExt;
        let Ok(name) = std::env::var("PQKEY_STATUS_CHILD") else {
            return;
        };
        let mut info = key_info(presence_named(&name));
        if let Some(bus) = std::env::var_os("PQKEY_STATUS_KEY_BUS") {
            info = info.with_session_bus((bus != "-").then_some(bus.as_bytes()));
        }
        let state_dir = default_state_dir();
        crate::state::ensure_state_dir(&state_dir).unwrap();
        let _key = publish_as_key(&state_dir, info);
        if let Ok(version) = std::env::var("PQKEY_STATUS_KEY_VERSION") {
            publish_as_version(&state_dir, &version);
        }
        let result = status(&state_dir);
        if let Err(err) = &result {
            errln!("pqkey: {err}");
        }
        std::process::exit(i32::from(crate::cli::exit_status(&result)));
    }

    /// `status` names a key that approves every request without asking, with
    /// the fix for how it runs: as the user service, or started by hand. It
    /// still exits with status 0. A key that asks, or that never answers,
    /// keeps its own problem and gets no such warning. Each child plays the
    /// key itself; a fake systemctl says the service is installed and
    /// enabled, and that the child is its main process, or, for a key
    /// started by hand, that it has none.
    #[test]
    fn status_names_a_key_that_approves_without_asking() {
        use std::process::Stdio;
        let dir = TempDir::new("status-presence");
        let bin = fake_systemctl(dir.path());
        let no_bus = format!("unix:path={}", dir.path().join("no-bus").display());
        let children: Vec<_> = [
            ("auto-approve", "service"),
            ("auto-approve", "by-hand"),
            ("unanswered", "service"),
            ("notify", "service"),
        ]
        .into_iter()
        .map(|(presence, runs)| {
            let child = child_test!(status_child)
                .command()
                .env("PQKEY_STATUS_CHILD", presence)
                .env("PQKEY_STATUS_RUNS", runs)
                .env("PATH", &bin)
                .env(
                    "XDG_DATA_HOME",
                    dir.path().join(format!("{presence}-{runs}")),
                )
                // No session bus there: a key that asks cannot.
                .env("DBUS_SESSION_BUS_ADDRESS", &no_bus)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            (presence, runs, child.id(), child)
        })
        .collect();
        for (presence, runs, pid, child) in children {
            let output = child.wait_with_output().unwrap();
            assert_ran(&output.stdout);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let context = format!("{presence} {runs}: {stdout}{stderr}");
            assert_eq!(output.status.code(), Some(0), "{context}");
            let named = |word: &str| listed(&stdout, word).unwrap_or_else(|| panic!("{context}"));
            match (presence, runs) {
                ("auto-approve", "service") => {
                    assert!(
                        stdout.contains(&format!(
                            "Key:      running (pid {pid}, systemd user service pqkey.service)\n"
                        )),
                        "{context}"
                    );
                    assert_problem(&named("auto-approve"), &AUTO_APPROVE, &SERVICE_FIX);
                }
                ("auto-approve", _) => {
                    assert!(
                        stdout.contains(&format!("Key:      running (pid {pid})\n")),
                        "{context}"
                    );
                    assert_problem(&named("auto-approve"), &AUTO_APPROVE, &BY_HAND_FIX);
                    // Its other problem, as before.
                    assert_names(&named("started by hand").what, &[&format!("(pid {pid})")]);
                }
                ("unanswered", _) => {
                    assert_problem(&named("never answers"), &UNANSWERED, &UNANSWERED_FIX);
                }
                _ => assert_names(
                    &named("cannot connect").what,
                    &["session bus", &format!("`{no_bus}`")],
                ),
            }
            if presence != "auto-approve" {
                assert!(!stdout.contains("auto-approve"), "{context}");
            }
        }
    }

    /// `status` names a unit file of the user's own where setup installs the
    /// unit, which setup keeps as it is, with a fix that keeps its changes in
    /// a drop-in; no unit file there, it does not. (Which units setup keeps:
    /// `platform::linux::daemon`'s tests.)
    #[test]
    fn status_names_a_unit_of_the_users_own_that_setup_keeps() {
        let dir = TempDir::new("status-kept-unit");
        let bin = fake_systemctl(dir.path());
        let unit = dir.path().join("config/systemd/user/pqkey.service");
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        let path = unit.display().to_string();
        for own in [true, false] {
            if own {
                std::fs::write(
                    &unit,
                    "[Service]\nExecStart=/usr/local/bin/pqkey run --presence unanswered\n",
                )
                .unwrap();
            } else {
                std::fs::remove_file(&unit).unwrap();
            }
            let output = child_test!(status_child)
                .command()
                .env("PQKEY_STATUS_CHILD", "notify")
                .env("PQKEY_STATUS_RUNS", "service")
                .env("PATH", &bin)
                .env("XDG_CONFIG_HOME", dir.path().join("config"))
                .env("XDG_DATA_HOME", dir.path().join(format!("data-{own}")))
                .env(
                    "DBUS_SESSION_BUS_ADDRESS",
                    format!("unix:path={}", dir.path().join("no-bus").display()),
                )
                .output()
                .unwrap();
            assert_ran(&output.stdout);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(output.status.code(), Some(0), "{own}: {output:?}");
            let kept = listed(&stdout, "keeps your own unit");
            if own {
                assert_problem(
                    &kept.unwrap_or_else(|| panic!("{stdout}")),
                    &["keeps your own unit", &path],
                    &[
                        "`systemctl --user edit pqkey`",
                        &format!("delete {path}"),
                        "`pqkey setup`",
                    ],
                );
            } else {
                assert_eq!(kept, None, "{stdout}");
            }
        }
    }

    /// `status` checks notifications on the session bus the key published,
    /// never on this terminal's: the bus in the key's DBUS_SESSION_BUS_ADDRESS,
    /// or without one `$XDG_RUNTIME_DIR/bus`. It names that bus, with the fix
    /// that gives the key a bus. A bus over TCP it never connects to, whether
    /// the key runs as the service or by hand: it says it cannot check it,
    /// with the same fix. Each child plays the key on a bus of its own, with
    /// no bus there; the test holds this terminal's bus and the TCP one, and
    /// counts the connections waiting there.
    #[test]
    fn status_checks_notifications_on_the_keys_own_session_bus() {
        use std::os::unix::net::UnixListener;
        use std::process::Stdio;
        let dir = TempDir::new("status-bus");
        let bin = fake_systemctl(dir.path());
        let terminal = dir.path().join("shell-bus");
        let terminal_bus = UnixListener::bind(&terminal).unwrap();
        let here = format!("unix:path={}", terminal.display());
        let tcp_bus = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = format!(
            "tcp:host=127.0.0.1,port={}",
            tcp_bus.local_addr().unwrap().port()
        );
        let key = format!("unix:path={}", dir.path().join("key-bus").display());
        let runtime = dir.path().join("runtime");
        let fallback = format!("unix:path={}/bus", runtime.display());
        let children: Vec<_> = [
            ("by-hand", key.clone(), key.clone()),
            ("service", "-".to_owned(), fallback),
            ("service", tcp.clone(), tcp.clone()),
            ("by-hand", tcp.clone(), tcp.clone()),
        ]
        .into_iter()
        .enumerate()
        .map(|(n, (runs, bus, named))| {
            let child = child_test!(status_child)
                .command()
                .env("PQKEY_STATUS_CHILD", "notify")
                .env("PQKEY_STATUS_RUNS", runs)
                .env("PQKEY_STATUS_KEY_BUS", &bus)
                .env("PATH", &bin)
                .env("XDG_DATA_HOME", dir.path().join(format!("data-{n}")))
                .env("XDG_RUNTIME_DIR", &runtime)
                .env("DBUS_SESSION_BUS_ADDRESS", &here)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            (format!("{runs} on {bus}"), named, child)
        })
        .collect();
        for (key_runs, named, child) in children {
            let output = child.wait_with_output().unwrap();
            assert_ran(&output.stdout);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let context = format!("{key_runs}: {stdout}{stderr}");
            assert_eq!(output.status.code(), Some(0), "{context}");
            // The cause, then the fix that gives the key the desktop's bus.
            let cause = if named == tcp {
                ["  ! pqkey cannot check", "session bus", named.as_str()]
            } else {
                ["  ! the key cannot connect", named.as_str(), "denied"]
            };
            let fix = [
                "\n    Fix: ",
                "systemctl --user import-environment DBUS_SESSION_BUS_ADDRESS",
                "pqkey stop && pqkey start",
            ];
            assert_names(&stdout, &[cause, fix].concat());
            // Its one notification problem, which never names this
            // terminal's bus.
            assert_eq!(stdout.matches("session bus").count(), 1, "{context}");
            assert!(!stdout.contains(&here), "{context}");
        }
        terminal_bus.set_nonblocking(true).unwrap();
        tcp_bus.set_nonblocking(true).unwrap();
        assert_eq!(std::iter::from_fn(|| terminal_bus.accept().ok()).count(), 0);
        assert_eq!(std::iter::from_fn(|| tcp_bus.accept().ok()).count(), 0);
    }

    /// `status` of a key another pqkey started. One too old to publish its
    /// session bus (`pqkey-daemon-v1`) gets the hint that status cannot check
    /// it, never a check of this terminal's bus. One whose information this
    /// pqkey cannot read at all, as from a newer pqkey, was not started by
    /// this version: it keeps running, so status says so after what it found
    /// on the device, and fails.
    #[test]
    fn status_of_a_key_another_pqkey_started() {
        use std::process::Stdio;
        let dir = TempDir::new("status-versions");
        let bin = fake_systemctl(dir.path());
        let here = format!("unix:path={}", dir.path().join("shell-bus").display());
        let children: Vec<_> = ["v1", "v3"]
            .into_iter()
            .map(|version| {
                let child = child_test!(status_child)
                    .command()
                    .env("PQKEY_STATUS_CHILD", "notify")
                    .env("PQKEY_STATUS_RUNS", "service")
                    .env("PQKEY_STATUS_KEY_VERSION", version)
                    .env("PATH", &bin)
                    .env("XDG_DATA_HOME", dir.path().join(version))
                    .env("DBUS_SESSION_BUS_ADDRESS", &here)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                (version, child.id(), child)
            })
            .collect();
        for (version, pid, child) in children {
            let output = child.wait_with_output().unwrap();
            assert_ran(&output.stdout);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let context = format!("{version}: {stdout}{stderr}");
            assert!(
                stdout.contains(&format!(
                    "Key:      running (pid {pid}, systemd user service pqkey.service)\n"
                )),
                "{context}"
            );
            if version == "v1" {
                assert_eq!(output.status.code(), Some(0), "{context}");
                assert_names(
                    &stdout,
                    &[
                        "  ! pqkey cannot check",
                        "session bus\n    Fix: ",
                        "systemctl --user import-environment DBUS_SESSION_BUS_ADDRESS",
                        "pqkey stop && pqkey start",
                    ],
                );
                assert!(!stdout.contains(&here), "{context}");
            } else {
                assert_eq!(output.status.code(), Some(1), "{context}");
                let error = stderr.lines().last().unwrap_or_default();
                assert!(error.starts_with("pqkey: "), "{context}");
                assert_names(
                    error,
                    &[
                        &format!("(pid {pid})"),
                        "not started by this version",
                        "`pqkey stop && pqkey start`",
                    ],
                );
            }
        }
    }

    /// A key that stops or restarts just as `status` finds it is starting or
    /// stopping, not a key that an older pqkey started. Here it removes its
    /// pid file, as a key that stops does first, while status asks systemd
    /// whether it is the service, before status reads what it published.
    #[test]
    fn status_finds_a_key_that_stops_meanwhile_starting_or_stopping() {
        let dir = TempDir::new("status-stops");
        let data = dir.path().join("data");
        let output = child_test!(status_child)
            .command()
            .env("PQKEY_STATUS_CHILD", "notify")
            .env("PQKEY_STATUS_RUNS", "service")
            // The default state directory under XDG_DATA_HOME.
            .env(
                "PQKEY_STATUS_STOPS",
                data.join("pqkey").join(crate::state_lock::PID_FILE),
            )
            .env("PATH", fake_systemctl(dir.path()))
            .env("XDG_DATA_HOME", &data)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", dir.path().join("no-bus").display()),
            )
            .output()
            .unwrap();
        assert_ran(&output.stdout);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let context = format!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(output.status.code(), Some(0), "{context}");
        assert!(
            stdout.contains("Key:      starting or stopping\n"),
            "{context}"
        );
        assert!(!stdout.contains("Key:      running"), "{context}");
    }

    /// The child of `status_reads_what_the_key_published_once`: this process
    /// plays a key run with the presence `PQKEY_STATUS_CHILD` names on the
    /// state directory `PQKEY_STATUS_READS` names, runs `pqkey status`, and
    /// says how often it opened what the key published.
    #[test]
    fn status_reads_child() {
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        let (Ok(name), Some(state_dir)) = (
            std::env::var("PQKEY_STATUS_CHILD"),
            std::env::var_os("PQKEY_STATUS_READS"),
        ) else {
            return;
        };
        let state_dir = std::path::PathBuf::from(state_dir);
        let _key = run_as_key(&state_dir, presence_named(&name));
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).unwrap();
        // Closes too, so that two opens in a row are not merged into one event.
        inotify
            .add_watch(
                &state_dir.join(crate::state_lock::INFO_FILE),
                AddWatchFlags::IN_OPEN | AddWatchFlags::IN_CLOSE_NOWRITE,
            )
            .unwrap();
        let result = status(&state_dir);
        let mut opens = 0;
        while let Ok(events) = inotify.read_events() {
            if events.is_empty() {
                break;
            }
            opens += events
                .iter()
                .filter(|event| event.mask.contains(AddWatchFlags::IN_OPEN))
                .count();
        }
        errln!("opens of authenticator.info: {opens}");
        if let Err(err) = &result {
            errln!("pqkey: {err}");
        }
        std::process::exit(i32::from(crate::cli::exit_status(&result)));
    }

    /// `status` reads what the running key published once, so that a key
    /// that restarts meanwhile cannot fail a second read as if an older pqkey
    /// had started it: for a key that asks, whose bus is checked, and one
    /// that approves without asking, which is warned about.
    #[test]
    fn status_reads_what_the_key_published_once() {
        use std::process::Stdio;
        let dir = TempDir::new("status-reads");
        let children: Vec<_> = ["notify", "auto-approve"]
            .into_iter()
            .map(|presence| {
                let state_dir = dir.path().join(presence);
                std::fs::create_dir(&state_dir).unwrap();
                let child = child_test!(status_reads_child)
                    .command()
                    .env("PQKEY_STATUS_CHILD", presence)
                    .env("PQKEY_STATUS_READS", &state_dir)
                    .env(
                        "DBUS_SESSION_BUS_ADDRESS",
                        format!("unix:path={}", dir.path().join("no-bus").display()),
                    )
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                (presence, child)
            })
            .collect();
        for (presence, child) in children {
            let output = child.wait_with_output().unwrap();
            assert_ran(&output.stdout);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let context = format!("{presence}: {stdout}{stderr}");
            assert_eq!(output.status.code(), Some(0), "{context}");
            assert!(
                stderr.contains("opens of authenticator.info: 1\n"),
                "{context}"
            );
        }
    }

    /// Flip the last byte of `path`, as a media error would.
    fn damage_file(path: &Path) {
        let mut contents = std::fs::read(path).unwrap();
        *contents.last_mut().unwrap() ^= 1;
        std::fs::write(path, contents).unwrap();
    }

    /// The record file that `insert` adds to `dir`.
    fn record_added(dir: &Path, insert: impl FnOnce()) -> std::path::PathBuf {
        let files = || -> Vec<_> {
            std::fs::read_dir(dir)
                .map(|entries| {
                    entries
                        .map(|entry| entry.unwrap().path())
                        .filter(|path| path.is_file())
                        .collect()
                })
                .unwrap_or_default()
        };
        let before = files();
        insert();
        let added: Vec<_> = files()
            .into_iter()
            .filter(|path| !before.contains(path))
            .collect();
        let [added] = added.as_slice() else {
            panic!("one new record in {}: {added:?}", dir.display());
        };
        added.clone()
    }

    /// A key's store in `dir` with three passkeys, and their records, oldest
    /// first: in a legacy store all three in `credentials/`; in the managed
    /// layout, a legacy one the upgrade kept, at `credential-set/<hash>`,
    /// then two in `credential-set/records/`.
    fn store_with_passkeys(dir: &Path, managed: bool) -> Vec<std::path::PathBuf> {
        let mut store = FileStore::open(dir).unwrap();
        let mut files = Vec::new();
        for id in 1..=3 {
            let passkey = discoverable("example.com", id, "user", CoseAlg::ES256);
            files.push(if managed && id > 1 {
                record_added(&dir.join("credential-set").join("records"), || {
                    store.insert_or_replace_discoverable(&passkey).unwrap();
                })
            } else {
                record_added(&dir.join("credentials"), || store.put(&passkey).unwrap())
            });
        }
        if managed {
            files[0] = dir
                .join("credential-set")
                .join(files[0].file_name().unwrap());
        }
        files
    }

    /// What a report says fails after damage of a kind.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Fails {
        /// Registration and the damaged records' credentials, which the key
        /// does not count either.
        Records(u64),
        /// Registration, use and listing: membership metadata is damaged.
        Membership,
        /// The passkeys that were in a legacy store's lost directory.
        LegacyDirectory,
        /// Sign-ins that count on the shared signature counter; passkeys
        /// count on their own, and the key counts them all.
        Counter,
        /// Registration, sign-ins and a new PIN: the PIN state is damaged,
        /// and the key takes the PIN for blocked; it counts every passkey.
        PinState,
        /// The large blobs sites stored; the key counts every passkey.
        LargeBlobs,
        /// The store cannot be checked.
        Unchecked,
    }

    /// Damage the store in `dir` with record `files` as `damage` says, and
    /// return the start of what `status` names, and what fails.
    fn damage(dir: &Path, damage: &str, files: &[std::path::PathBuf]) -> (String, Fails) {
        let set = dir.join("credential-set");
        let relative = |path: &Path| path.strip_prefix(dir).unwrap().display().to_string();
        let named = |path: &Path, fault: &str| format!("({} {fault}", relative(path));
        match damage {
            "record" => {
                damage_file(&files[2]);
                (named(&files[2], "is corrupt"), Fails::Records(998))
            }
            "removed record" => {
                std::fs::remove_file(&files[2]).unwrap();
                (named(&files[2], "is missing"), Fails::Records(998))
            }
            "kept record" | "legacy record" => {
                damage_file(&files[0]);
                (named(&files[0], "is corrupt"), Fails::Records(998))
            }
            "removed kept record" => {
                std::fs::remove_file(&files[0]).unwrap();
                (named(&files[0], "is missing"), Fails::Records(998))
            }
            "records directory" => {
                std::fs::remove_dir_all(set.join("records")).unwrap();
                let first = files[1..].iter().min().unwrap();
                (named(first, "is missing"), Fails::Records(999))
            }
            "manifest" => {
                damage_file(&set.join("active"));
                (
                    "(credential-set/active is corrupt".into(),
                    Fails::Membership,
                )
            }
            "removed manifest" => {
                std::fs::remove_file(set.join("active")).unwrap();
                (
                    "(credential-set/active is missing".into(),
                    Fails::Membership,
                )
            }
            "unreadable manifest" => {
                std::fs::remove_file(set.join("active")).unwrap();
                std::fs::create_dir(set.join("active")).unwrap();
                (
                    "(credential-set/active cannot be read".into(),
                    Fails::Membership,
                )
            }
            "marker" => {
                damage_file(&dir.join("credential-format"));
                ("(credential-format is corrupt".into(), Fails::Membership)
            }
            "removed marker" => {
                std::fs::remove_file(dir.join("credential-format")).unwrap();
                ("(credential-format is missing".into(), Fails::Membership)
            }
            "managed directory" => {
                std::fs::remove_dir_all(&set).unwrap();
                ("(credential-set is missing".into(), Fails::Membership)
            }
            "legacy directory" => {
                std::fs::remove_dir_all(dir.join("credentials")).unwrap();
                ("(credentials is missing".into(), Fails::LegacyDirectory)
            }
            "counter" => {
                FileStore::open(dir)
                    .unwrap()
                    .set_signature_counter(5)
                    .unwrap();
                damage_file(&dir.join("signature-counter"));
                ("(signature-counter is corrupt".into(), Fails::Counter)
            }
            "pin state" => {
                let mut pin = PinStateRecord::default();
                pin.pin_hash = Some(*pqkey_ctap::platform::pin_hash(b"1234"));
                FileStore::open(dir).unwrap().set_pin_state(&pin).unwrap();
                damage_file(&dir.join("pin-state"));
                ("(pin-state is corrupt".into(), Fails::PinState)
            }
            "large blobs" => {
                FileStore::open(dir)
                    .unwrap()
                    .set_large_blob_array(&pqkey_ctap::store::INITIAL_LARGE_BLOB_ARRAY)
                    .unwrap();
                damage_file(&dir.join("large-blobs"));
                ("(large-blobs is corrupt".into(), Fails::LargeBlobs)
            }
            "short key" => {
                std::fs::write(dir.join("keys").join("credential.key"), b"short").unwrap();
                ("credential root key unavailable".into(), Fails::Unchecked)
            }
            _ => unreachable!("{damage}"),
        }
    }

    /// The lines the key logged as it started about its credential store
    /// on `dir`, with their levels: those that report it and name `dir`.
    fn start_up_lines(dir: &TempDir) -> Vec<(log::Level, String)> {
        let mut lines = crate::test_support::logs::containing(&dir.path().display().to_string());
        lines.retain(|(_, line)| line.starts_with("the credential store "));
        lines
    }

    /// [`store_problem`] of the store in `dir`, inspected as `status` does.
    fn problem_in(dir: &Path) -> Option<Problem> {
        store_problem(dir, FileStore::inspect_in(dir))
    }

    /// For healthy stores `status` shows what it showed, whatever the
    /// layout: the room for more passkeys and no credential store problem,
    /// before the key has created its state directory, which `status` does
    /// not create either, too.  The key logs nothing about the store as it
    /// starts.
    #[test]
    fn status_of_a_healthy_store_is_unchanged() {
        crate::test_support::logs::install();
        let dir = TempDir::new("status-healthy");
        let missing = dir.path().join("missing");
        assert_eq!(problem_in(&missing), None);
        assert!(!missing.exists(), "status creates no state directory");
        let mut store = FileStore::open(dir.path()).unwrap();
        assert_eq!(problem_in(dir.path()), None, "a new store");
        store
            .put(&discoverable("example.com", 1, "alice", CoseAlg::ES256))
            .unwrap();
        assert_eq!(problem_in(dir.path()), None, "a legacy store");
        drop(store);
        {
            let (_daemon, mut key) = start(&dir);
            assert_eq!(
                passkeys_status(&key.info().unwrap()),
                "Passkeys: room for 999 more"
            );
        }
        FileStore::open(dir.path())
            .unwrap()
            .insert_or_replace_discoverable(&discoverable(
                "example.com",
                2,
                "bob",
                CoseAlg::MLDSA65,
            ))
            .unwrap();
        let (_daemon, mut key) = start(&dir);
        assert_eq!(
            passkeys_status(&key.info().unwrap()),
            "Passkeys: room for 998 more"
        );
        assert_eq!(problem_in(dir.path()), None, "an upgraded store");
        assert_eq!(start_up_lines(&dir), []);
    }

    /// `status` reports each kind of damage to the credential store as the
    /// key logs it when it starts: the same files, what fails, and what to
    /// do; the key starts all the same.  Where the report says passkeys
    /// cannot be listed, `pqkey passkeys` cannot list them, and where the key
    /// cannot count its passkeys, the passkeys line says so.  A damaged PIN
    /// state or large-blob array is moved out of the state directory rather
    /// than repaired, and the PIN state's fix sets a new PIN; where it blocks
    /// the PIN, the PIN line says so, and names no reset.
    #[test]
    fn status_and_start_up_report_each_kind_of_damage_alike() {
        crate::test_support::logs::install();
        for kind in [
            "record",
            "removed record",
            "kept record",
            "removed kept record",
            "legacy record",
            "records directory",
            "manifest",
            "removed manifest",
            "unreadable manifest",
            "marker",
            "removed marker",
            "managed directory",
            "legacy directory",
            "counter",
            "pin state",
            "large blobs",
            "short key",
        ] {
            let dir = TempDir::new("status-damage");
            let legacy = matches!(kind, "legacy record" | "legacy directory");
            let files = store_with_passkeys(dir.path(), !legacy);
            let (named, fails) = damage(dir.path(), kind, &files);
            let problem = problem_in(dir.path()).unwrap_or_else(|| panic!("{kind}: no problem"));
            let state = match fails {
                Fails::Unchecked => "cannot be checked",
                _ => "is damaged",
            };
            let shown = dir.path().display();
            let fix = match fails {
                Fails::PinState => vec![
                    "`pqkey stop`".to_owned(),
                    format!("move pin-state out of {shown}"),
                    "`pqkey start`".to_owned(),
                    "`pqkey pin`".to_owned(),
                    "`pqkey config`".to_owned(),
                    "`pqkey reset`".to_owned(),
                    "last resort".to_owned(),
                ],
                Fails::LargeBlobs => vec![
                    "`pqkey stop`".to_owned(),
                    format!("move large-blobs out of {shown}"),
                    "`pqkey start`".to_owned(),
                ],
                _ => vec![
                    "`pqkey stop`".to_owned(),
                    format!("a copy of {shown}"),
                    "`pqkey repair`".to_owned(),
                    "`pqkey start`".to_owned(),
                    "`pqkey reset`".to_owned(),
                    "last resort".to_owned(),
                ],
            };
            let fix: Vec<&str> = fix.iter().map(String::as_str).collect();
            assert_problem(&problem, &["credential store", state, &named], &fix);

            let (_daemon, mut key) = start(&dir);
            let level = match fails {
                Fails::Unchecked => log::Level::Warn,
                _ => log::Level::Error,
            };
            assert_eq!(
                start_up_lines(&dir),
                [(level, format!("{}. S{}", problem.what, &problem.fix[1..]))],
                "{kind}"
            );
            let counted = passkeys_status(&key.info().unwrap());
            match fails {
                Fails::Records(room) => {
                    assert_eq!(counted, format!("Passkeys: room for {room} more"), "{kind}");
                }
                Fails::Membership => {
                    assert_eq!(counted, "Passkeys: cannot be counted", "{kind}");
                    key.set_pin(b"1234").unwrap();
                    let token = key.management_token(b"1234").unwrap();
                    assert!(
                        matches!(
                            key.passkeys(&token),
                            Err(ClientError::Status(CTAP2_ERR_PROCESSING))
                        ),
                        "{kind}"
                    );
                }
                Fails::LegacyDirectory => {
                    // Opening the store created the directory again, empty:
                    // the key counts and lists no passkey, which is why the
                    // report claims no more than that those in it are lost.
                    assert_eq!(counted, "Passkeys: room for 1000 more", "{kind}");
                    key.set_pin(b"1234").unwrap();
                    let token = key.management_token(b"1234").unwrap();
                    assert_eq!(key.passkeys(&token).unwrap(), []);
                    assert_eq!(problem_in(dir.path()), None, "{kind}");
                }
                Fails::Counter => {
                    assert_eq!(counted, "Passkeys: room for 997 more", "{kind}");
                    assert_names(
                        &problem.what,
                        &[
                            &named,
                            "cannot sign in",
                            "as a security key",
                            "did not store",
                        ],
                    );
                }
                Fails::PinState => {
                    assert_eq!(counted, "Passkeys: room for 997 more", "{kind}");
                    assert!(matches!(
                        key.management_token(b"1234"),
                        Err(ClientError::Status(CTAP2_ERR_PIN_BLOCKED))
                    ));
                    let damage = FileStore::inspect_in(dir.path()).unwrap();
                    let line = pin_state(key.pin_retries().unwrap(), &damage);
                    assert_names(
                        &line,
                        &[
                            "blocked",
                            "pin-state is damaged",
                            "set a new PIN",
                            "fix below",
                        ],
                    );
                    assert!(!line.contains("reset"), "{line}");
                }
                Fails::LargeBlobs => {
                    assert_eq!(counted, "Passkeys: room for 997 more", "{kind}");
                    assert!(!problem.fix.contains("reset"), "{problem:?}");
                }
                Fails::Unchecked => {
                    assert_eq!(counted, "Passkeys: cannot be counted", "{kind}");
                }
            }
        }
    }

    /// A legacy store whose `credentials` directory is lost while the key
    /// runs: `status` reports it, the key cannot count its passkeys, and it
    /// logs the loss as `status` reported it when it starts again, which
    /// creates the directory again, empty.
    #[test]
    fn a_legacy_directory_lost_while_the_key_runs_is_reported_alike() {
        crate::test_support::logs::install();
        let dir = TempDir::new("status-lost-directory");
        store_with_passkeys(dir.path(), false);
        let (daemon, mut key) = start(&dir);
        std::fs::remove_dir_all(dir.path().join("credentials")).unwrap();
        let problem = problem_in(dir.path()).expect("a lost directory is a problem");
        assert_names(
            &problem.what,
            &["credential store", "is damaged", "(credentials is missing)"],
        );
        assert_eq!(
            passkeys_status(&key.info().unwrap()),
            "Passkeys: cannot be counted"
        );
        assert_eq!(start_up_lines(&dir), []);
        drop((daemon, key));
        let (_daemon, _key) = start(&dir);
        assert_eq!(
            start_up_lines(&dir),
            [(
                log::Level::Error,
                format!("{}. S{}", problem.what, &problem.fix[1..])
            )]
        );
        assert_eq!(problem_in(dir.path()), None);
    }
}
