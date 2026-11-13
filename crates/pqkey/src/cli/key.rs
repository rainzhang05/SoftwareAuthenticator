//! The commands that manage the running key: `status`, `pin`, `config`,
//! `passkeys` and `reset`.
//!
//! They talk to the key over CTAP through its platform client link, as a
//! security
//! key's management application does ([`crate::client`]). So the key itself
//! checks the PIN and counts retries, asks its user to approve a reset, and
//! accepts a reset only shortly after it is plugged in.

use std::{
    io::{self, BufRead, Write},
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use pqkey_ctap::CoseAlg;
use pqkey_ctap::ctap::constants::{
    CTAP2_ERR_KEEPALIVE_CANCEL, CTAP2_ERR_KEY_STORE_FULL, CTAP2_ERR_NOT_ALLOWED,
    CTAP2_ERR_OPERATION_DENIED, CTAP2_ERR_PIN_AUTH_BLOCKED, CTAP2_ERR_PIN_BLOCKED,
    CTAP2_ERR_PIN_INVALID, CTAP2_ERR_PIN_NOT_SET, CTAP2_ERR_PIN_POLICY_VIOLATION,
    CTAP2_ERR_PROCESSING, CTAP2_ERR_PUAT_REQUIRED, CTAP2_ERR_USER_ACTION_TIMEOUT,
};
use pqkey_ctap::store::{
    DirectoryFlush, FileStore, StoreError, damage_fix, damage_summary, damage_unchecked,
};
use signal_hook::{consts::SIGINT, flag};

use super::ConfigAction;
use super::checks::Problem;
use super::daemon::{self, Running};
use super::daemon_info::DaemonInfo;
use super::output::{self, errln, outln};
use crate::client::ctap2::{Authenticator, ClientError, Info, Passkey, PinRetries, Token};
use crate::client::ctaphid::{ReportLink, STATUS_UPNEEDED};
use crate::pin_input::{MIN_PIN_CODE_POINTS, Pin, PinReader, PinSource, validate_pin};
use crate::platform::{self, ClientLink};
use crate::platform::{System, UserService};
use crate::presence::notification::{ConnectError, Keep, NotificationServer, ServerInfo, sanitise};
use crate::service;
use crate::state::{Room, default_state_dir};

/// How long to wait for the running key's device and for access to it.
const DEVICE_WAIT: Duration = Duration::from_secs(5);
/// The same for `status`, which only reports what it finds, and for the look
/// `reset` takes at the PIN before it restarts the key.
const STATUS_WAIT: Duration = Duration::from_secs(1);

/// What re-plugging the key takes, for the messages that ask for it.
const REPLUG: &str = "pqkey stop && pqkey start";

fn not_running() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "the key is not running; start it with `pqkey start`",
    )
}

fn client_error(err: ClientError) -> io::Error {
    match err {
        ClientError::Hid(crate::client::ctaphid::HidError::Io(err)) => err,
        ClientError::Hid(err @ crate::client::ctaphid::HidError::Busy) => {
            io::Error::new(io::ErrorKind::ResourceBusy, err.to_string())
        }
        err => io::Error::other(err.to_string()),
    }
}

/// The running key on `state_dir`, through its platform client link.
fn connect(state_dir: &Path) -> io::Result<Authenticator<ClientLink>> {
    let running = daemon::running(state_dir)?.ok_or_else(not_running)?;
    connect_to(running, DEVICE_WAIT).map(|(_, key)| key)
}

/// The display label and CTAPHID channel of the key `running`, waiting up
/// to `wait` for its device and access to it.
fn connect_to(running: Running, wait: Duration) -> io::Result<(String, Authenticator<ClientLink>)> {
    let (path, link) = open_node(running, wait)?;
    let key = Authenticator::open(link).map_err(client_error)?;
    Ok((path, key))
}

/// Open the selected platform's client link to this daemon's device.
fn open_node(running: Running, wait: Duration) -> io::Result<(String, ClientLink)> {
    platform::open_client(
        &service::device_uniq(running.pid().as_raw().unsigned_abs()),
        wait,
    )
}

/// Ask `question` on the terminal; only "y" or "yes" is a yes.
fn confirm(question: &str) -> io::Result<bool> {
    ask(question, false)
}

/// Ask `question` on the terminal. An empty answer is `default_yes`.
pub(crate) fn ask(question: &str, default_yes: bool) -> io::Result<bool> {
    {
        let mut stderr = io::stderr().lock();
        let choices = if default_yes { "[Y/n]" } else { "[y/N]" };
        write!(stderr, "{question} {choices} ")?;
        stderr.flush()?;
    }
    // Standard input's own buffer, which PIN lines read before were taken
    // from: a reader of its own could swallow lines meant for later.
    let mut answer = String::new();
    if io::stdin().lock().read_line(&mut answer)? == 0 {
        return Ok(false);
    }
    Ok(is_yes(&answer, default_yes))
}

fn is_yes(answer: &str, default_yes: bool) -> bool {
    match answer.trim().to_ascii_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// status

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
            show_key(running)?;
            let info = info?;
            problems.extend(running_problems_of(&system, running, &info, STATUS_WAIT)?);
            problems.extend(presence_problem(&info.1, running));
        }
    }
    problems.extend(state_dir_problem(state_dir, running.is_some()));
    // Checking the credential store decrypts every credential: keep them out
    // of core files, and this process out of reach, as the daemon does.
    platform::disable_core_dumps()?;
    problems.extend(store_problem(state_dir));
    problems.extend(service_problems(state_dir, running)?);
    if !problems.is_empty() {
        outln!()?;
        output::problems(&problems)?;
    }
    Ok(())
}

/// The lines of `status` about the running key itself.
fn show_key(running: Running) -> io::Result<()> {
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
            outln!("PIN:      {}", pin_state(retries))?;
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

fn policy_status(info: &Info) -> Vec<&'static str> {
    let mut lines = Vec::new();
    if info.always_uv == Some(true) {
        lines.push("Always UV: on; registrations and sign-ins require the PIN");
    }
    if info.force_pin_change == Some(true) {
        lines.push("PIN change required; run `pqkey pin`");
    }
    lines
}

fn minimum_pin_length(info: &Info) -> usize {
    info.min_pin_length
        .and_then(|minimum| usize::try_from(minimum).ok())
        .unwrap_or(MIN_PIN_CODE_POINTS)
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
/// options are `info`. Notifications are checked on the key's own session bus,
/// or on this process's: for a key of an older pqkey, which did not publish
/// it, and for one started by hand on a bus over TCP, which status does not
/// connect to (`System::key_notification_problem`).
fn running_problems_of(
    system: &System,
    running: Running,
    (info, args): &(DaemonInfo, super::DaemonArgs),
    wait: Duration,
) -> io::Result<Vec<Problem>> {
    let mut problems = system.device_problems(running.pid(), wait)?;
    match args.presence {
        super::PresenceArg::Notify => problems.extend(match info.session_bus_address() {
            Some(address) => {
                system.key_notification_problem(matches!(running, Running::Service(_)), &address)?
            }
            None => system.notification_problem(&notification_server())?,
        }),
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
            format!(
                "remount that filesystem read-write (one the kernel made read-only after an \
                 error needs `fsck` first){start}"
            ),
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
        format!(
            "free some space on that filesystem (`df -h` and `df -i` show what each one has \
             left){start}"
        ),
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

/// A credential store in `state_dir` that is damaged, with what fails, or
/// that cannot be checked, and what to do: what the key logs as it starts
/// (`service::log_if_store_damaged`). It is read as it is, while the key may
/// change it ([`FileStore::inspect`]).
fn store_problem(state_dir: &Path) -> Option<Problem> {
    let fix = || damage_fix(&state_dir.display().to_string());
    match FileStore::inspect_in(state_dir) {
        Ok(damage) if damage.is_empty() => None,
        Ok(damage) => Some(Problem::new(damage_summary(&damage), fix())),
        Err(err) => Some(Problem::new(damage_unchecked(&err), fix())),
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
/// directory, as `pqkey setup` arranges, and starts it with the session.
fn service_problems(state_dir: &Path, running: Option<Running>) -> io::Result<Vec<Problem>> {
    if state_dir != default_state_dir() {
        return Ok(Vec::new());
    }
    let mut problems = UserService::problems(running.is_some())?;
    if let Some(Running::Daemon(pid)) = running
        && daemon::uses_service(state_dir)?
    {
        problems.push(UserService::manual_start_problem(pid)?);
    }
    Ok(problems)
}

/// How often `pqkey setup` asks for a new PIN that was mistyped.
const PIN_ATTEMPTS: usize = 3;

/// The last step of `pqkey setup`: a PIN on the key `running`, which
/// browsers ask for before they use passkeys. Asked for on a terminal, and
/// again if it was mistyped. Returns whether the key has a PIN now.
pub fn ensure_pin(running: Running, interactive: bool) -> io::Result<()> {
    let (_, mut key) = connect_to(running, DEVICE_WAIT).map_err(|err| {
        io::Error::new(err.kind(), format!(
            "cannot communicate with the key: {err}; check `pqkey status` and rerun `pqkey setup`"
        ))
    })?;
    ensure_pin_on(&mut key, interactive, &mut PinReader::from_stdin()).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("{err}; run `pqkey pin`, then `pqkey setup`"),
        )
    })
}

/// Uses the same CTAP client in setup and socket-backed regression tests.
fn ensure_pin_on<L: ReportLink>(
    key: &mut Authenticator<L>,
    interactive: bool,
    pins: &mut dyn PinSource,
) -> io::Result<()> {
    let info = key.info().map_err(client_error)?;
    match info.pin_set {
        Some(true) if info.force_pin_change != Some(true) => {
            check_pin_usable(key)?;
            return output::done("PIN is set");
        }
        Some(_) if !interactive => {
            return Err(io::Error::other(
                "PIN setup is incomplete; run `pqkey pin` in a terminal, then `pqkey setup`",
            ));
        }
        Some(true) => {
            outln!("The key requires a different PIN meeting its current policy.")?;
            set_or_change_pin(key, pins)?;
        }
        Some(false) => {
            outln!()?;
            let minimum = minimum_pin_length(&info);
            outln!("Choose a PIN for the key, at least {minimum} characters.")?;
            set_first_pin(key, pins)?;
        }
        None => {
            return Err(io::Error::other(
                "the key does not support the required PIN",
            ));
        }
    }
    let info = key.info().map_err(client_error)?;
    if info.pin_set != Some(true) || info.force_pin_change == Some(true) {
        return Err(io::Error::other("PIN setup is incomplete; run `pqkey pin`"));
    }
    check_pin_usable(key)?;
    output::done("PIN setup complete")
}

/// Set a PIN on `key`, which has none, asking `pins` again for one that was
/// mistyped: too short, or not the same twice.
fn set_first_pin<L: ReportLink>(
    key: &mut Authenticator<L>,
    pins: &mut dyn PinSource,
) -> io::Result<()> {
    let mut attempt = 1;
    loop {
        match set_or_change_pin(key, pins) {
            Ok(_) => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::InvalidInput && attempt < PIN_ATTEMPTS => {
                errln!("{err}; try again.");
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

/// The PIN line of `status`.  For a blocked PIN it says to restart the key
/// first, which clears a block that came from a PIN state the key could not
/// read, and only then to reset it, which erases the passkeys.
fn pin_state(retries: PinRetries) -> String {
    if retries.retries == 0 {
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

// ---------------------------------------------------------------------------
// pin

/// What `pqkey pin` did.
#[derive(Debug, PartialEq, Eq)]
enum PinChange {
    Set,
    Changed,
}

/// `pqkey pin`.
pub fn pin(state_dir: &Path) -> io::Result<()> {
    let mut key = connect(state_dir)?;
    match set_or_change_pin(&mut key, &mut PinReader::from_stdin())? {
        PinChange::Set => outln!("PIN set."),
        PinChange::Changed => outln!("PIN changed."),
    }
}

/// setPIN on a key without a PIN, changePIN on one with a PIN.
fn set_or_change_pin<L: ReportLink>(
    key: &mut Authenticator<L>,
    pins: &mut dyn PinSource,
) -> io::Result<PinChange> {
    let info = key.info().map_err(client_error)?;
    let minimum = minimum_pin_length(&info);
    match info.pin_set {
        Some(false) => {
            let new = pins.new_pin(minimum)?;
            key.set_pin(new.as_bytes()).map_err(|err| match err {
                // The key could not store the PIN: it could not write its
                // state, or refused to where its state directory cannot keep
                // one, which `status` reports.
                ClientError::Status(CTAP2_ERR_PROCESSING) => io::Error::other(
                    "the key could not store the PIN; `pqkey status` says whether its state \
                     directory can keep one, and `journalctl --user -u pqkey` says why",
                ),
                err => new_pin_error(key, err, minimum, false),
            })?;
            Ok(PinChange::Set)
        }
        Some(true) => {
            check_pin_usable(key)?;
            let current = plausible_pin(pins.current_pin()?)?;
            let new = pins.new_pin(minimum)?;
            let same_pin = *current == *new;
            key.change_pin(current.as_bytes(), new.as_bytes())
                .map_err(|err| new_pin_error(key, err, minimum, same_pin))?;
            Ok(PinChange::Changed)
        }
        None => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the key does not support a PIN",
        )),
    }
}

fn new_pin_error<L: ReportLink>(
    key: &mut Authenticator<L>,
    err: ClientError,
    minimum: usize,
    same_pin: bool,
) -> io::Error {
    if matches!(err, ClientError::Status(CTAP2_ERR_PIN_POLICY_VIOLATION)) {
        let updated = key.info().ok();
        let mut message = if same_pin
            && updated
                .as_ref()
                .is_some_and(|info| info.force_pin_change == Some(true))
        {
            "the new PIN must differ from the current PIN when a change is required; \
             run `pqkey pin` and choose another PIN"
                .into()
        } else {
            let minimum = updated.as_ref().map_or(minimum, minimum_pin_length);
            if updated
                .as_ref()
                .is_some_and(|info| info.pin_complexity_policy == Some(true))
            {
                format!("choose a PIN with at least {minimum} characters")
            } else {
                format!("the new PIN is too short; choose at least {minimum} characters")
            }
        };
        if updated
            .as_ref()
            .is_some_and(|info| info.pin_complexity_policy == Some(true))
        {
            message = format!(
                "the new PIN must contain at least one ASCII letter (A-Z or a-z) and one ASCII digit (0-9), meet the minimum length, and use at most 63 UTF-8 bytes; {message}"
            );
        }
        return io::Error::new(io::ErrorKind::InvalidInput, message);
    }
    pin_error(key, err)
}

fn token_error<L: ReportLink>(key: &mut Authenticator<L>, err: ClientError) -> io::Error {
    if matches!(err, ClientError::Status(CTAP2_ERR_PIN_POLICY_VIOLATION)) {
        return io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the key requires a PIN change; run `pqkey pin` before trying again",
        );
    }
    pin_error(key, err)
}

/// Refuse before asking for the PIN when the key would refuse any PIN.
fn check_pin_usable<L: ReportLink>(key: &mut Authenticator<L>) -> io::Result<()> {
    let retries = key.pin_retries().map_err(client_error)?;
    if retries.retries == 0 {
        Err(pin_error_message(
            &ClientError::Status(CTAP2_ERR_PIN_BLOCKED),
            None,
        ))
    } else if retries.power_cycle_needed {
        Err(pin_error_message(
            &ClientError::Status(CTAP2_ERR_PIN_AUTH_BLOCKED),
            None,
        ))
    } else {
        Ok(())
    }
}

/// `pin`, unless it could never have been set: then it is wrong without the
/// key spending a retry on it, as when Enter is pressed by accident.
fn plausible_pin(pin: Pin) -> io::Result<Pin> {
    match validate_pin(&pin) {
        Ok(()) => Ok(pin),
        Err(err) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("wrong PIN: {err}, so it cannot be the key's (no retry was used)"),
        )),
    }
}

/// The error for a PIN the key refused, with the retries left after a wrong
/// one.
fn pin_error<L: ReportLink>(key: &mut Authenticator<L>, err: ClientError) -> io::Error {
    let retries = match err {
        ClientError::Status(CTAP2_ERR_PIN_INVALID) => key.pin_retries().ok(),
        _ => None,
    };
    pin_error_message(&err, retries)
}

fn pin_error_message(err: &ClientError, retries: Option<PinRetries>) -> io::Error {
    use io::ErrorKind::{InvalidInput, PermissionDenied};
    let ClientError::Status(status) = err else {
        return io::Error::other(err.to_string());
    };
    let (kind, message) = match *status {
        CTAP2_ERR_PIN_INVALID => (
            PermissionDenied,
            match retries {
                Some(PinRetries { retries: 1, .. }) => {
                    "wrong PIN; 1 retry left, after which only a reset makes the key usable again"
                        .into()
                }
                Some(PinRetries { retries, .. }) => format!("wrong PIN; {retries} retries left"),
                None => "wrong PIN".into(),
            },
        ),
        CTAP2_ERR_PIN_AUTH_BLOCKED => (
            PermissionDenied,
            format!(
                "the key refuses PIN checks after 3 wrong PINs in a row until it is plugged in \
                 again: {REPLUG}"
            ),
        ),
        CTAP2_ERR_PIN_BLOCKED => (
            PermissionDenied,
            format!(
                "the PIN is blocked: it was entered wrongly too often, or the key could not read \
                 or write its PIN state. Restart the key ({REPLUG}) and try again; if the PIN is \
                 still blocked, only a reset makes the key usable again (`pqkey reset`), and it \
                 erases every passkey and large blob on it"
            ),
        ),
        CTAP2_ERR_PIN_POLICY_VIOLATION => (
            InvalidInput,
            "the key does not accept this PIN as the new one".into(),
        ),
        CTAP2_ERR_PIN_NOT_SET => (
            InvalidInput,
            "the key has no PIN; `pqkey pin` sets one".into(),
        ),
        _ => return io::Error::other(err.to_string()),
    };
    io::Error::new(kind, message)
}

// ---------------------------------------------------------------------------
// config

/// `pqkey config`, and its authenticated configuration changes.
pub(super) fn config(state_dir: &Path, action: Option<&ConfigAction>) -> io::Result<()> {
    let mut key = connect(state_dir)?;
    for line in configure(&mut key, &mut PinReader::from_stdin(), action, &mut confirm)? {
        outln!("{line}")?;
    }
    Ok(())
}

fn config_lines(info: &Info) -> Vec<String> {
    vec![
        format!("Always UV: {}", on_off(info.always_uv == Some(true))),
        format!("Minimum PIN length: {}", minimum_pin_length(info)),
        format!(
            "PIN complexity: {}",
            on_off(info.pin_complexity_policy == Some(true))
        ),
        format!(
            "PIN change required: {}",
            if info.force_pin_change == Some(true) {
                "yes"
            } else {
                "no"
            }
        ),
    ]
}

fn on_off(enabled: bool) -> &'static str {
    if enabled { "on" } else { "off" }
}

fn config_token<L: ReportLink>(
    key: &mut Authenticator<L>,
    pins: &mut dyn PinSource,
    info: &Info,
) -> io::Result<Option<Token>> {
    if info.pin_set != Some(true) {
        return Ok(None);
    }
    acquire_pin_token(key, pins, Authenticator::config_token).map(Some)
}

fn acquire_pin_token<L: ReportLink>(
    key: &mut Authenticator<L>,
    pins: &mut dyn PinSource,
    request: fn(&mut Authenticator<L>, &[u8]) -> Result<Token, ClientError>,
) -> io::Result<Token> {
    check_pin_usable(key)?;
    let pin = plausible_pin(pins.pin()?)?;
    request(key, pin.as_bytes()).map_err(|err| token_error(key, err))
}

fn configure<L: ReportLink>(
    key: &mut Authenticator<L>,
    pins: &mut dyn PinSource,
    action: Option<&ConfigAction>,
    confirmation: &mut dyn FnMut(&str) -> io::Result<bool>,
) -> io::Result<Vec<String>> {
    let info = key.info().map_err(client_error)?;
    let Some(action) = action else {
        return Ok(config_lines(&info));
    };
    let subcommand = match action {
        ConfigAction::AlwaysUv { .. } => 2,
        ConfigAction::MinPinLength { .. }
        | ConfigAction::ForcePinChange
        | ConfigAction::PinComplexity { .. } => 3,
    };
    if info.authenticator_config != Some(true) || !info.config_commands.contains(&subcommand) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the key does not support this configuration command; update pqkey and restart it",
        ));
    }
    let mut lines = Vec::new();
    match action {
        ConfigAction::AlwaysUv { setting } => {
            if (info.always_uv == Some(true)) != setting.enabled() {
                let token = config_token(key, pins, &info)?;
                key.toggle_always_uv(token.as_ref())
                    .map_err(|err| config_error(key, err, &info))?;
            }
            let updated = key.info().map_err(client_error)?;
            lines.push(format!(
                "Always UV: {}.",
                on_off(updated.always_uv == Some(true))
            ));
            if updated.pin_set == Some(false) {
                lines.push(
                    "Browsers will need a PIN before they can register or sign in; \
                     `pqkey pin` sets one."
                        .into(),
                );
            }
        }
        ConfigAction::MinPinLength {
            minimum,
            rp_ids,
            yes,
        } => {
            if !yes
                && !confirmation(&format!(
                    "Set the minimum PIN length to {minimum}? Only a reset, which erases every \
                     passkey and large blob, can lower it again."
                ))?
            {
                return Ok(vec!["Nothing was changed.".into()]);
            }
            let token = config_token(key, pins, &info)?;
            let rp_ids = if rp_ids.is_empty() {
                None
            } else {
                Some(rp_ids.as_slice())
            };
            key.set_min_pin_length(token.as_ref(), Some(*minimum), rp_ids, None, None)
                .map_err(|err| config_error(key, err, &info))?;
            let updated = key.info().map_err(client_error)?;
            lines.push(format!(
                "Minimum PIN length: {}.",
                minimum_pin_length(&updated)
            ));
            if updated.force_pin_change == Some(true) {
                lines.push("A PIN change is required; run `pqkey pin`.".into());
            }
        }
        ConfigAction::PinComplexity { yes } => {
            let enabled = info.pin_complexity_policy.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the key does not support PIN complexity; update pqkey and restart it",
                )
            })?;
            if !enabled {
                if !yes
                    && !confirmation(
                        "Enable PIN complexity, requiring at least one ASCII letter (A-Z or a-z) and one ASCII digit (0-9)? Only a reset, which erases every passkey and large blob, can disable it. An existing PIN must change.",
                    )?
                {
                    return Ok(vec!["Nothing was changed.".into()]);
                }
                let token = config_token(key, pins, &info)?;
                key.set_min_pin_length(token.as_ref(), None, None, None, Some(true))
                    .map_err(|err| config_error(key, err, &info))?;
            }
            let updated = key.info().map_err(client_error)?;
            lines.push(format!(
                "PIN complexity: {}.",
                on_off(updated.pin_complexity_policy == Some(true))
            ));
            if updated.force_pin_change == Some(true) {
                lines.push("A PIN change is required; run `pqkey pin`.".into());
            }
        }
        ConfigAction::ForcePinChange => {
            if info.pin_set != Some(true) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the key has no PIN to change; `pqkey pin` sets one",
                ));
            }
            let token = config_token(key, pins, &info)?;
            key.set_min_pin_length(token.as_ref(), None, None, Some(true), None)
                .map_err(|err| config_error(key, err, &info))?;
            lines.push("A PIN change is required; run `pqkey pin`.".into());
        }
    }
    Ok(lines)
}

fn config_error<L: ReportLink>(
    key: &mut Authenticator<L>,
    err: ClientError,
    info: &Info,
) -> io::Error {
    let message = match err {
        ClientError::RequestTooLarge {
            encoded_bytes,
            limit,
        } => format!(
            "the encoded CTAP2 request is {encoded_bytes} bytes; the limit is {limit} bytes; \
             shorten the RP list (use fewer or shorter RP IDs)"
        ),
        ClientError::Status(CTAP2_ERR_PIN_POLICY_VIOLATION) => format!(
            "the minimum PIN length cannot be lowered below {}; only `pqkey reset` lowers \
             it, and erases every passkey and large blob",
            minimum_pin_length(info)
        ),
        ClientError::Status(CTAP2_ERR_KEY_STORE_FULL) => format!(
            "the key cannot store that RP ID list; use at most {} RP IDs, each at most 253 bytes",
            info.max_rp_ids_for_min_pin_length.unwrap_or(8)
        ),
        ClientError::Status(CTAP2_ERR_PUAT_REQUIRED) if info.pin_set == Some(false) => {
            "always-UV requires a PIN for this change; set one with `pqkey pin`, or turn \
             always-UV off with `pqkey config always-uv off` first"
                .into()
        }
        _ => return pin_error(key, err),
    };
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

// ---------------------------------------------------------------------------
// passkeys

/// A pinUvAuthToken with the credential management permission, for which
/// the user enters the PIN.
fn management_token<L: ReportLink>(
    key: &mut Authenticator<L>,
    pins: &mut dyn PinSource,
) -> io::Result<Token> {
    if key.info().map_err(client_error)?.pin_set != Some(true) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "passkeys are managed with the key's PIN, and it has none; `pqkey pin` sets one",
        ));
    }
    acquire_pin_token(key, pins, Authenticator::management_token)
}

/// `pqkey passkeys`.
pub fn list_passkeys(state_dir: &Path) -> io::Result<()> {
    let mut key = connect(state_dir)?;
    if key.info().map_err(client_error)?.pin_set != Some(true) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "passkeys are managed with the key's PIN, and it has none; `pqkey pin` sets one",
        ));
    }
    let token = acquire_pin_token(
        &mut key,
        &mut PinReader::from_stdin(),
        Authenticator::listing_token,
    )?;
    let passkeys = key.passkeys(&token).map_err(client_error)?;
    if passkeys.is_empty() {
        outln!("No passkeys are stored on the key.")?;
        return outln!("{NOT_LISTED}");
    }
    for line in passkey_table(&passkeys) {
        outln!("{line}")?;
    }
    Ok(())
}

/// `pqkey passkeys delete QUERY`.
pub fn delete_passkey(state_dir: &Path, query: &str, yes: bool) -> io::Result<()> {
    let mut key = connect(state_dir)?;
    let token = management_token(&mut key, &mut PinReader::from_stdin())?;
    let passkeys = key.passkeys(&token).map_err(client_error)?;
    let passkey = matching_passkey(&passkeys, query)?;
    let question = format!(
        "Delete the passkey of {} for {}? Signing in with it stops working; the site keeps its \
         record of it until you remove it there.",
        user(passkey),
        site(passkey)
    );
    if !yes && !confirm(&question)? {
        errln!("Nothing was deleted.");
        return Ok(());
    }
    key.delete(&token, &passkey.credential_id)
        .map_err(client_error)?;
    outln!("Passkey deleted.")
}

/// Why a registration can be missing from `pqkey passkeys`: a credential that
/// is not discoverable requires the site to supply its ID. Whether sealed
/// or stored, credential management does not list it.
const NOT_LISTED: &str = "A site that registered it as a security key (a second factor), or \
                          before the PIN was set,\nkeeps that sign-in itself: it works, but is \
                          not listed here.";

/// Columns of [`passkey_table`].
const HEADINGS: [&str; 5] = ["SITE", "USER", "ALGORITHM", "PAYMENT", "ID"];
/// The most of a site or user name the table shows.
const MAX_COLUMN_CHARS: usize = 40;
/// Hex digits of a credential ID the table shows: enough to tell passkeys
/// apart, and to name one in `pqkey passkeys delete`.
const SHORT_ID_DIGITS: usize = 16;

/// The relying party, as safe to print: websites choose these, and must not
/// get escape sequences onto the terminal.
fn site(passkey: &Passkey) -> String {
    shown_site(&passkey.rp_id).unwrap_or_else(|| "-".into())
}

/// The user's name and display name, as safe to print.
fn user(passkey: &Passkey) -> String {
    shown_user(&passkey.user_name, &passkey.user_display_name).unwrap_or_else(|| "-".into())
}

/// The RP ID `rp_id`, as safe to print, or `None` if nothing printable is
/// left of it.
pub(super) fn shown_site(rp_id: &str) -> Option<String> {
    sanitise(rp_id, MAX_COLUMN_CHARS, Keep::End)
}

/// A user's `name` and `display` name, as safe to print, or `None` if
/// nothing printable is left of either.
pub(super) fn shown_user(name: &Option<String>, display: &Option<String>) -> Option<String> {
    let clean = |name: &Option<String>| {
        name.as_deref()
            .and_then(|name| sanitise(name, MAX_COLUMN_CHARS, Keep::Start))
    };
    match (clean(name), clean(display)) {
        (Some(name), Some(display)) if name != display => Some(format!("{name} ({display})")),
        (Some(name), _) | (None, Some(name)) => Some(name),
        (None, None) => None,
    }
}

fn algorithm(alg: Option<i64>) -> String {
    let Some(alg) = alg else {
        return "-".into();
    };
    match i32::try_from(alg).ok().map(CoseAlg::try_from) {
        Some(Ok(alg)) => alg.name().into(),
        Some(Err(_)) | None => format!("COSE {alg}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The passkeys as an aligned table, sorted by site and user, with a heading.
fn passkey_table(passkeys: &[Passkey]) -> Vec<String> {
    let mut rows: Vec<([String; 4], bool)> = passkeys
        .iter()
        .map(|passkey| {
            let mut id = hex(&passkey.credential_id);
            id.truncate(SHORT_ID_DIGITS);
            (
                [site(passkey), user(passkey), algorithm(passkey.alg), id],
                passkey.third_party_payment == Some(true),
            )
        })
        .collect();
    // The new display column must not change the original ordering.
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let rows: Vec<_> = rows
        .into_iter()
        .map(|([site, user, alg, id], payment)| {
            [
                site,
                user,
                alg,
                if payment { "enabled" } else { "-" }.into(),
                id,
            ]
        })
        .collect();
    let mut widths = HEADINGS.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    std::iter::once(HEADINGS.map(String::from))
        .chain(rows)
        .map(|row| {
            let mut line = String::new();
            for (column, (cell, width)) in row.iter().zip(widths).enumerate() {
                if column + 1 == HEADINGS.len() {
                    line.push_str(cell);
                } else {
                    let padding = width - cell.chars().count();
                    line.push_str(cell);
                    line.extend(std::iter::repeat_n(' ', padding + 2));
                }
            }
            line
        })
        .collect()
}

/// The one passkey whose site, user name, display name or hex ID contains
/// `query`, ignoring case.
fn matching_passkey<'a>(passkeys: &'a [Passkey], query: &str) -> io::Result<&'a Passkey> {
    let needle = query.to_lowercase();
    if needle.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "name the passkey to delete by part of its site, user or ID",
        ));
    }
    let contains = |text: &str| text.to_lowercase().contains(&needle);
    let matches: Vec<&Passkey> = passkeys
        .iter()
        .filter(|passkey| {
            contains(&passkey.rp_id)
                || passkey.user_name.as_deref().is_some_and(contains)
                || passkey.user_display_name.as_deref().is_some_and(contains)
                || contains(&hex(&passkey.credential_id))
        })
        .collect();
    match matches[..] {
        [passkey] => Ok(passkey),
        [] => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no passkey matches \"{query}\"; `pqkey passkeys` lists them"),
        )),
        _ => {
            let owned: Vec<Passkey> = matches.into_iter().cloned().collect();
            let table = passkey_table(&owned).join("\n");
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "\"{query}\" matches {} passkeys; name one by more of its site, user or ID:\n{table}",
                    owned.len()
                ),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// reset

/// `pqkey reset`.
///
/// CTAP 2.3 §6.6: "In order to prevent accidental trigger of this mechanism,
/// some form of user approval MAY be performed on the authenticator itself,
/// meaning that the platform will need to give the user an indication that
/// the authenticator is waiting for this approval." and, for authenticators
/// without a display, "the request MUST have come to the authenticator within
/// 10 seconds of powering up". So the key is plugged in afresh, as one would
/// a hardware key, and left as it was found afterwards.  Should the restart
/// unblock the PIN, the user is asked again before anything is erased
/// ([`restarted_for_reset`]).
pub fn reset(state_dir: &Path, yes: bool) -> io::Result<()> {
    let running = daemon::running(state_dir)?;
    if !yes
        && !confirm(
            "Reset the key? Its passkeys, large blobs and PIN are erased, and signing in with \
             those passkeys stops working. This cannot be undone.",
        )?
    {
        errln!("Nothing was reset.");
        return Ok(());
    }
    // A key that could not be restarted is left as the failed restart left
    // it.
    let mut restarted = false;
    let result = restarted_for_reset(
        yes,
        &mut || {
            let (_, link) = open_node(running?, STATUS_WAIT).ok()?;
            Authenticator::open_within(link, STATUS_WAIT).ok()
        },
        &mut || {
            let running = daemon::replug(state_dir)?;
            restarted = true;
            connect_to(running, DEVICE_WAIT).map(|(_, key)| key)
        },
        &mut confirm,
    )
    .and_then(|key| key.map(reset_key).transpose());
    let restored = if running.is_some() || !restarted {
        Ok(())
    } else {
        daemon::unplug(state_dir).map(drop)
    };
    let reset = result?;
    restored?;
    if reset.is_none() {
        errln!("Nothing was reset.");
        return Ok(());
    }
    outln!("The key is reset: its passkeys, large blobs and PIN are erased.")
}

/// The key restarted with `replug`, for a reset within 10 seconds of its
/// start, or `None` if the user decides to keep it after all.
///
/// A restart clears a block that came from a PIN state the key could not
/// read.  So when its PIN was blocked before the restart (`before` reaches
/// the key as it runs, if it does) and no longer is, the user is told and
/// asked again before anything is erased; on a yes the key is restarted once
/// more, since answering can take longer than its reset window lasts.  With
/// `yes` nothing is checked or asked: the key is restarted for the reset, as
/// `pqkey reset --yes` always did.
fn restarted_for_reset<L: ReportLink>(
    yes: bool,
    before: &mut dyn FnMut() -> Option<Authenticator<L>>,
    replug: &mut dyn FnMut() -> io::Result<Authenticator<L>>,
    confirmation: &mut dyn FnMut(&str) -> io::Result<bool>,
) -> io::Result<Option<Authenticator<L>>> {
    let blocked = !yes && before().is_some_and(|mut key| matches!(pin_blocked(&mut key), Ok(true)));
    let mut key = replug()?;
    if !blocked {
        return Ok(Some(key));
    }
    let now = match pin_blocked(&mut key) {
        Ok(true) => return Ok(Some(key)),
        Ok(false) => "The PIN is no longer blocked now that the key has restarted, and it can \
                      be used again."
            .to_owned(),
        Err(err) => format!(
            "The key could not say after its restart whether the PIN is still blocked ({err})."
        ),
    };
    if !confirmation(&format!(
        "{now} Reset the key anyway? Its passkeys, large blobs and PIN are erased, and signing \
         in with those passkeys stops working. This cannot be undone."
    ))? {
        return Ok(None);
    }
    drop(key);
    replug().map(Some)
}

/// Whether the key has a PIN and it is blocked, as `status` and the PIN
/// commands tell.
fn pin_blocked<L: ReportLink>(key: &mut Authenticator<L>) -> Result<bool, ClientError> {
    Ok(key.info()?.pin_set == Some(true) && key.pin_retries()?.retries == 0)
}

/// authenticatorReset, which the user approves in a notification; Ctrl-C
/// cancels it, and a second Ctrl-C ends pqkey.
fn reset_key<L: ReportLink>(key: Authenticator<L>) -> io::Result<()> {
    let cancel = Arc::new(AtomicBool::new(false));
    // Registered in this order, the first action only sees the flag the
    // second set on an earlier Ctrl-C.
    flag::register_conditional_default(SIGINT, Arc::clone(&cancel))?;
    flag::register(SIGINT, Arc::clone(&cancel))?;
    let mut key = key.with_cancel_flag(cancel);
    let mut asked = false;
    key.reset(&mut |status| {
        if status == STATUS_UPNEEDED && !asked {
            asked = true;
            errln!("Approve the reset in the notification on your desktop (Ctrl-C cancels).");
        }
    })
    .map_err(reset_error)
}

fn reset_error(err: ClientError) -> io::Error {
    let ClientError::Status(status) = err else {
        return client_error(err);
    };
    let message = match status {
        CTAP2_ERR_OPERATION_DENIED => "the reset was denied; nothing was erased",
        CTAP2_ERR_USER_ACTION_TIMEOUT => "the reset was not approved in time; nothing was erased",
        CTAP2_ERR_KEEPALIVE_CANCEL => "the reset was cancelled; nothing was erased",
        CTAP2_ERR_NOT_ALLOWED => {
            "the key refused the reset: it accepts one only within 10 seconds of starting. \
             Nothing was erased; try again"
        }
        _ => return client_error(ClientError::Status(status)),
    };
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use unicode_normalization::UnicodeNormalization;

    use pqkey_ctap::store::{CredentialStore, FileStore};

    use super::*;
    use crate::client::tests::{Daemon, TestLink, discoverable, start};
    use crate::test_support::TempDir;

    /// PINs from a script; reading past its end fails.
    struct Script(VecDeque<&'static str>);

    impl Script {
        fn of(pins: &[&'static str]) -> Self {
            Self(pins.iter().copied().collect())
        }

        fn next(&mut self) -> io::Result<Pin> {
            self.0
                .pop_front()
                .map(|pin| Pin::new(pin.nfc().collect()))
                .ok_or_else(|| io::Error::other("asked for a PIN the script does not have"))
        }
    }

    impl PinSource for Script {
        fn pin(&mut self) -> io::Result<Pin> {
            self.next()
        }

        fn current_pin(&mut self) -> io::Result<Pin> {
            self.next()
        }

        fn new_pin(&mut self, minimum: usize) -> io::Result<Pin> {
            let pin = self.next()?;
            crate::pin_input::validate_new_pin(&pin, minimum)?;
            Ok(pin)
        }
    }

    fn retries<L: ReportLink>(key: &mut Authenticator<L>) -> u64 {
        key.pin_retries().unwrap().retries
    }

    /// Where `part` starts in `text`, which must contain it.
    fn at(text: &str, part: &str) -> usize {
        text.find(part)
            .unwrap_or_else(|| panic!("{part:?} is not in {text:?}"))
    }

    /// Block the PIN of `key`, which runs on `dir`, until the key restarts:
    /// it finds its PIN state corrupt for a moment, as when another program
    /// has replaced the file, and treats the PIN as blocked from then on,
    /// while a restart reads the state again, intact.
    fn block_pin_until_restart<L: ReportLink>(dir: &TempDir, key: &mut Authenticator<L>) {
        let path = dir.path().join("pin-state");
        let stored = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"not a PIN state").unwrap();
        // getInfo reads the PIN state again.
        assert_eq!(key.info().unwrap().pin_set, Some(true));
        std::fs::write(&path, stored).unwrap();
        assert_eq!(retries(key), 0);
    }

    /// The key on `dir` as `pqkey reset` sees it: restarted by `replug`.
    struct Replugged<'a> {
        dir: &'a TempDir,
        daemon: Option<Daemon>,
        restarts: usize,
    }

    impl<'a> Replugged<'a> {
        fn new(dir: &'a TempDir, daemon: Daemon) -> Self {
            Self {
                dir,
                daemon: Some(daemon),
                restarts: 0,
            }
        }

        fn replug(&mut self) -> io::Result<Authenticator<TestLink>> {
            // The old key stops before the new one opens the store.
            self.daemon = None;
            let (daemon, key) = start(self.dir);
            self.daemon = Some(daemon);
            self.restarts += 1;
            Ok(key)
        }

        /// [`restarted_for_reset`] with `before` as the key before the
        /// restart, answering `answer` to every question; with `None`, a
        /// question fails the test.  Returns the key to reset, and the
        /// questions.
        fn reset(
            &mut self,
            yes: bool,
            before: Authenticator<TestLink>,
            answer: Option<bool>,
        ) -> (Option<Authenticator<TestLink>>, Vec<String>) {
            let mut before = Some(before);
            let mut questions = Vec::new();
            let key = restarted_for_reset(
                yes,
                &mut || {
                    assert!(!yes, "--yes looks at nothing before the restart");
                    before.take()
                },
                &mut || self.replug(),
                &mut |question| {
                    questions.push(question.to_owned());
                    Ok(answer.unwrap_or_else(|| panic!("asked again: {question}")))
                },
            )
            .unwrap();
            (key, questions)
        }
    }

    /// A running key on `dir` with a PIN and one passkey, its PIN blocked
    /// until it restarts.
    fn blocked_key(dir: &TempDir) -> (Replugged<'_>, Authenticator<TestLink>) {
        FileStore::open(dir.path())
            .unwrap()
            .put(&discoverable("example.com", 1, "alice", CoseAlg::ES256))
            .unwrap();
        let (daemon, mut key) = start(dir);
        key.set_pin(b"1234").unwrap();
        block_pin_until_restart(dir, &mut key);
        (Replugged::new(dir, daemon), key)
    }

    /// Check that nothing was erased: the key on `keys`, restarted, still has
    /// its PIN, with every retry, and its passkey.
    fn nothing_erased(keys: &mut Replugged<'_>) {
        let mut key = keys.replug().unwrap();
        assert_eq!(retries(&mut key), 8);
        let token = management_token(&mut key, &mut Script::of(&["1234"])).unwrap();
        assert_eq!(key.passkeys(&token).unwrap().len(), 1);
    }

    /// Reset `key`, which must accept it, and check it is erased.
    fn erase<L: ReportLink>(mut key: Authenticator<L>) {
        key.reset(&mut |_| {}).unwrap();
        let info = key.info().unwrap();
        assert_eq!(info.pin_set, Some(false));
        assert_eq!(info.remaining_discoverable, Some(1000));
    }

    #[test]
    fn pin_sets_a_pin_and_then_changes_it() {
        let dir = TempDir::new("cli-pin");
        let (_daemon, mut key) = start(&dir);
        assert_eq!(
            set_or_change_pin(&mut key, &mut Script::of(&["1234"])).unwrap(),
            PinChange::Set
        );
        assert_eq!(
            set_or_change_pin(&mut key, &mut Script::of(&["1234", "5678"])).unwrap(),
            PinChange::Changed
        );
        assert!(key.management_token(b"5678").is_ok());
    }

    /// A PIN the key could not store names where to find out why: `status`,
    /// which reports a state directory that cannot keep one, and the log.
    #[test]
    fn a_pin_the_key_cannot_store_points_at_status_and_the_log() {
        let dir = TempDir::new("cli-pin-not-stored");
        let (_daemon, mut key) = start(&dir);
        // A directory in the PIN state's place fails its write before
        // anything is published, as CTAP2_ERR_PROCESSING.
        std::fs::create_dir_all(dir.path().join("pin-state").join("occupied")).unwrap();
        let message = set_or_change_pin(&mut key, &mut Script::of(&["1234"]))
            .unwrap_err()
            .to_string();
        assert!(message.contains("could not store the PIN"), "{message}");
        assert!(message.contains("`pqkey status`"), "{message}");
        assert!(message.contains("journalctl --user -u pqkey"), "{message}");
        assert_eq!(key.info().unwrap().pin_set, Some(false));
    }

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
        let writes = "but the key writes there as it starts and with every registration, sign-in \
                      and PIN entry";
        let start = ", then run `pqkey start`";
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
        let free = "free some space on that filesystem (`df -h` and `df -i` show what each one \
                    has left)";
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
            let what = format!(
                "the state directory /home/u/.local/share/pqkey is on a full filesystem ({left}), \
                 {writes}"
            );
            assert_eq!(
                state_fs_problem(dir, room(bytes, files, false), false),
                Some(Problem::new(&what, format!("{free}{start}"))),
                "{left}"
            );
            assert_eq!(
                state_fs_problem(dir, room(bytes, files, false), true),
                Some(Problem::new(&what, free)),
                "{left}"
            );
        }
        let read_only = format!(
            "the state directory /home/u/.local/share/pqkey is on a read-only filesystem, {writes}"
        );
        let remount = "remount that filesystem read-write (one the kernel made read-only after an \
                       error needs `fsck` first)";
        for (bytes, files) in [
            (Some(u64::MAX), Some(u64::MAX)),
            (Some(0), Some(0)),
            (None, None),
        ] {
            assert_eq!(
                state_fs_problem(dir, room(bytes, files, true), false),
                Some(Problem::new(&read_only, format!("{remount}{start}"))),
                "{bytes:?} {files:?}"
            );
            assert_eq!(
                state_fs_problem(dir, room(bytes, files, true), true),
                Some(Problem::new(&read_only, remount)),
                "{bytes:?} {files:?}"
            );
        }
        let unchecked = "the state directory /home/u/.local/share/pqkey cannot be checked \
                         (Input/output error (os error 5)), and the key may not be able to use it \
                         either";
        let check = "check that it is a directory of yours that you can read, under directories \
                     you can enter (`ls -ld` shows each one's owner and mode), and look in \
                     `journalctl -k` for disk errors";
        let failed = || Err(io::Error::from(nix::errno::Errno::EIO));
        assert_eq!(
            state_fs_problem(dir, failed(), false),
            Some(Problem::new(unchecked, format!("{check}{start}")))
        );
        assert_eq!(
            state_fs_problem(dir, failed(), true),
            Some(Problem::new(unchecked, check))
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
        for (state_dir, err) in [
            (file.join("pqkey"), "Not a directory (os error 20)"),
            (socket, "No such device or address (os error 6)"),
        ] {
            let problem = state_dir_problem(&state_dir, false).expect("a problem");
            assert_eq!(
                problem.what,
                format!(
                    "the state directory {} cannot be checked ({err}), and the key may not be \
                     able to use it either",
                    state_dir.display()
                )
            );
            assert!(
                problem.fix.ends_with("disk errors, then run `pqkey start`"),
                "{problem:?}"
            );
        }
    }

    /// What `status` and `setup` say about a key run with --presence
    /// auto-approve, and their fixes for the service and for a key started
    /// by hand.
    const AUTO_APPROVE: &str = "the key runs with --presence auto-approve: it approves every \
        registration, sign-in and reset without asking, so anything running as you can use your \
        passkeys unnoticed";
    const SERVICE_FIX: &str = "remove --presence auto-approve from the ExecStart= line that \
        `systemctl --user cat pqkey` shows, in the unit or drop-in file named above it, then run \
        `pqkey stop && pqkey setup`";
    const BY_HAND_FIX: &str =
        "run `pqkey stop`, then `pqkey start` without --presence auto-approve";

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
            let mut expected = system.device_problems(me, Duration::ZERO).unwrap();
            match presence {
                PresenceArg::Notify => {
                    assert_eq!(warnings, [None, None]);
                    continue;
                }
                PresenceArg::AutoApprove => assert_eq!(
                    warnings,
                    [
                        Some(Problem::new(AUTO_APPROVE, SERVICE_FIX)),
                        Some(Problem::new(AUTO_APPROVE, BY_HAND_FIX))
                    ]
                ),
                PresenceArg::Unanswered => {
                    assert_eq!(warnings, [None, None]);
                    expected.push(Problem::new(
                        "the configured presence provider never answers requests",
                        "configure the service to use --presence notify where `systemctl --user \
                         cat pqkey` shows --presence unanswered, then run `pqkey stop && pqkey \
                         setup`",
                    ));
                }
            }
            for running in [Running::Service(me), Running::Daemon(me)] {
                assert_eq!(
                    running_problems(dir.path(), &system, running, Duration::ZERO).unwrap(),
                    expected,
                    "{presence:?}"
                );
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
        use std::process::{Command, Stdio};
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
            let child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cli::key::tests::status_child", "--nocapture"])
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
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let context = format!("{presence} {runs}: {stdout}{stderr}");
            assert_eq!(output.status.code(), Some(0), "{context}");
            let named =
                |fix: &str| stdout.contains(&format!("  ! {AUTO_APPROVE}\n    Fix: {fix}\n"));
            match (presence, runs) {
                ("auto-approve", "service") => {
                    assert!(
                        stdout.contains(&format!(
                            "Key:      running (pid {pid}, systemd user service pqkey.service)\n"
                        )),
                        "{context}"
                    );
                    assert!(named(SERVICE_FIX), "{context}");
                }
                ("auto-approve", _) => {
                    assert!(
                        stdout.contains(&format!("Key:      running (pid {pid})\n")),
                        "{context}"
                    );
                    assert!(named(BY_HAND_FIX), "{context}");
                    // Its other problem, as before.
                    assert!(
                        stdout.contains(&format!("  ! the key (pid {pid}) was started by hand")),
                        "{context}"
                    );
                }
                ("unanswered", _) => assert!(
                    stdout.contains(
                        "  ! the configured presence provider never answers requests\n    Fix: \
                         configure the service to use --presence notify where `systemctl --user \
                         cat pqkey` shows --presence unanswered, then run `pqkey stop && pqkey \
                         setup`\n"
                    ),
                    "{context}"
                ),
                _ => assert!(
                    stdout.contains(&format!(
                        "  ! the key cannot connect to its session bus (failed to connect to \
                         `{no_bus}`: "
                    )),
                    "{context}"
                ),
            }
            if presence != "auto-approve" {
                assert!(!stdout.contains("auto-approve"), "{context}");
            }
        }
    }

    /// `status` checks notifications on the session bus the key published,
    /// not on its own: the bus in the key's DBUS_SESSION_BUS_ADDRESS, or
    /// without one `$XDG_RUNTIME_DIR/bus`. It names that bus, and gives the
    /// fix that gives the key a bus. For the user service, which its unit
    /// allows only Unix sockets, a bus over TCP is the problem itself; for a
    /// key started by hand, status does not connect to a TCP address it read
    /// from the key, and checks its own bus instead. Each child plays the key
    /// on a bus of its own, with no bus there, and has another as its own
    /// session bus.
    #[test]
    fn status_checks_notifications_on_the_keys_own_session_bus() {
        use std::process::{Command, Stdio};
        let dir = TempDir::new("status-bus");
        let bin = fake_systemctl(dir.path());
        let here = format!("unix:path={}", dir.path().join("shell-bus").display());
        let key = format!("unix:path={}", dir.path().join("key-bus").display());
        let runtime = dir.path().join("runtime");
        let fallback = format!("unix:path={}/bus", runtime.display());
        let tcp = "tcp:host=127.0.0.1,port=9";
        let denied = "so every registration, sign-in and reset is denied";
        let import = "    Fix: in a terminal of your desktop session, run `systemctl --user \
                      import-environment DBUS_SESSION_BUS_ADDRESS`, then `pqkey stop && pqkey \
                      start`\n";
        let cannot_connect = |address: &str| {
            format!(
                "  ! the key cannot connect to its session bus (failed to connect to \
                 `{address}`: No such file or directory (os error 2)), {denied}\n{import}"
            )
        };
        let children: Vec<_> = [
            ("by-hand", key.clone(), cannot_connect(&key)),
            ("service", "-".to_owned(), cannot_connect(&fallback)),
            (
                "service",
                tcp.to_owned(),
                format!(
                    "  ! the key's session bus ({tcp}) is not a Unix socket, which the user \
                     service cannot use (its unit allows only Unix sockets), {denied}\n    Fix: \
                     in a terminal of a desktop session whose session bus is a Unix socket (its \
                     address starts with unix:), run `systemctl --user import-environment \
                     DBUS_SESSION_BUS_ADDRESS`, then `pqkey stop && pqkey start`\n"
                ),
            ),
            (
                "by-hand",
                tcp.to_owned(),
                format!(
                    "  ! there is no D-Bus session bus (failed to connect to `{here}`: No such \
                     file or directory (os error 2)), {denied}\n{import}"
                ),
            ),
        ]
        .into_iter()
        .enumerate()
        .map(|(n, (runs, bus, expected))| {
            let child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cli::key::tests::status_child", "--nocapture"])
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
            (format!("{runs} on {bus}"), expected, child)
        })
        .collect();
        for (key_runs, expected, child) in children {
            let output = child.wait_with_output().unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let context = format!("{key_runs}: {stdout}{stderr}");
            assert_eq!(output.status.code(), Some(0), "{context}");
            assert!(stdout.contains(&expected), "{context}");
            // Its one notification problem: this process's bus, which has
            // none either, gives no other fix, and is named only where it
            // stands in.
            assert_eq!(stdout.matches(denied).count(), 1, "{context}");
            assert_eq!(
                stdout.contains(&here),
                key_runs == format!("by-hand on {tcp}"),
                "{context}"
            );
        }
    }

    /// `status` of a key another pqkey started. One too old to publish its
    /// session bus (`pqkey-daemon-v1`) has notifications checked on this
    /// terminal's bus, which the problem names. One whose information this
    /// pqkey cannot read at all, as from a newer pqkey, was not started by
    /// this version: it keeps running, so status says so after what it found
    /// on the device, and fails.
    #[test]
    fn status_of_a_key_another_pqkey_started() {
        use std::process::{Command, Stdio};
        let dir = TempDir::new("status-versions");
        let bin = fake_systemctl(dir.path());
        let here = format!("unix:path={}", dir.path().join("shell-bus").display());
        let children: Vec<_> = ["v1", "v3"]
            .into_iter()
            .map(|version| {
                let child = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "cli::key::tests::status_child", "--nocapture"])
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
                assert!(
                    stdout.contains(&format!(
                        "  ! there is no D-Bus session bus (failed to connect to `{here}`: No \
                         such file or directory (os error 2)), so every registration, sign-in \
                         and reset is denied\n    Fix: in a terminal of your desktop session, \
                         run `systemctl --user import-environment DBUS_SESSION_BUS_ADDRESS`, then \
                         `pqkey stop && pqkey start`\n"
                    )),
                    "{context}"
                );
            } else {
                assert_eq!(output.status.code(), Some(1), "{context}");
                assert!(
                    stderr.contains(&format!(
                        "pqkey: the key (pid {pid}) was not started by this version of pqkey; \
                         restart it with `pqkey stop && pqkey start` first\n"
                    )),
                    "{context}"
                );
            }
        }
    }

    /// Where the key cannot ask on its own bus, `status` tries this
    /// terminal's, the one its DBUS_SESSION_BUS_ADDRESS names, as a bus to
    /// move the key to. One that never answers is none, and the key keeps its
    /// own fix. The test holds that bus's socket and counts the connections
    /// waiting there.
    #[test]
    fn status_tries_this_terminals_bus_for_a_key_that_cannot_ask() {
        use std::os::unix::net::UnixListener;
        use std::process::Command;
        let dir = TempDir::new("status-terminal-bus");
        let terminal = dir.path().join("terminal-bus");
        let listener = UnixListener::bind(&terminal).unwrap();
        let key = format!("unix:path={}", dir.path().join("key-bus").display());
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cli::key::tests::status_child", "--nocapture"])
            .env("PQKEY_STATUS_CHILD", "notify")
            .env("PQKEY_STATUS_RUNS", "service")
            .env("PQKEY_STATUS_KEY_BUS", &key)
            .env("PATH", fake_systemctl(dir.path()))
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", terminal.display()),
            )
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let context = format!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(output.status.code(), Some(0), "{context}");
        assert!(
            stdout.contains(&format!(
                "  ! the key cannot connect to its session bus (failed to connect to `{key}`: No \
                 such file or directory (os error 2)), so every registration, sign-in and reset \
                 is denied\n    Fix: in a terminal of your desktop session, run `systemctl --user \
                 import-environment DBUS_SESSION_BUS_ADDRESS`, then `pqkey stop && pqkey start`\n"
            )),
            "{context}"
        );
        listener.set_nonblocking(true).unwrap();
        let tried = std::iter::from_fn(|| listener.accept().ok()).count();
        assert_eq!(tried, 1, "{context}");
    }

    /// A key that stops or restarts just as `status` finds it is starting or
    /// stopping, not a key that an older pqkey started. Here it removes its
    /// pid file, as a key that stops does first, while status asks systemd
    /// whether it is the service, before status reads what it published.
    #[test]
    fn status_finds_a_key_that_stops_meanwhile_starting_or_stopping() {
        use std::process::Command;
        let dir = TempDir::new("status-stops");
        let data = dir.path().join("data");
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cli::key::tests::status_child", "--nocapture"])
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
        use std::process::{Command, Stdio};
        let dir = TempDir::new("status-reads");
        let children: Vec<_> = ["notify", "auto-approve"]
            .into_iter()
            .map(|presence| {
                let state_dir = dir.path().join(presence);
                std::fs::create_dir(&state_dir).unwrap();
                let child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "cli::key::tests::status_reads_child",
                        "--nocapture",
                    ])
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
            "short key" => {
                std::fs::write(dir.join("keys").join("credential.key"), b"short").unwrap();
                ("credential root key unavailable".into(), Fails::Unchecked)
            }
            _ => unreachable!("{damage}"),
        }
    }

    /// The lines the key logged as it started about its credential store
    /// on `dir`, with their levels: those that tell to keep a copy of it.
    fn start_up_lines(dir: &TempDir) -> Vec<(log::Level, String)> {
        crate::test_support::logs::containing(&format!("keep a copy of {}", dir.path().display()))
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
        assert_eq!(store_problem(&missing), None);
        assert!(!missing.exists(), "status creates no state directory");
        let mut store = FileStore::open(dir.path()).unwrap();
        assert_eq!(store_problem(dir.path()), None, "a new store");
        store
            .put(&discoverable("example.com", 1, "alice", CoseAlg::ES256))
            .unwrap();
        assert_eq!(store_problem(dir.path()), None, "a legacy store");
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
        assert_eq!(store_problem(dir.path()), None, "an upgraded store");
        assert_eq!(start_up_lines(&dir), []);
    }

    /// `status` reports each kind of damage to the credential store as the
    /// key logs it when it starts: the same files, what fails, and what to
    /// do; the key starts all the same.  Where the report says passkeys
    /// cannot be listed, `pqkey passkeys` cannot list them, and where the key
    /// cannot count its passkeys, the passkeys line says so.
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
            "short key",
        ] {
            let dir = TempDir::new("status-damage");
            let legacy = matches!(kind, "legacy record" | "legacy directory");
            let files = store_with_passkeys(dir.path(), !legacy);
            let (named, fails) = damage(dir.path(), kind, &files);
            let problem = store_problem(dir.path()).unwrap_or_else(|| panic!("{kind}: no problem"));
            let what = match fails {
                Fails::Unchecked => format!("the credential store cannot be checked: {named}"),
                _ => format!("the credential store is damaged {named}"),
            };
            assert!(problem.what.starts_with(&what), "{kind}: {problem:?}");
            assert_eq!(
                problem.fix,
                format!(
                    "stop the key with `pqkey stop`, keep a copy of {}, run `pqkey repair`, then \
                     start the key again with `pqkey start`; `pqkey reset` erases every passkey, \
                     so use it only as a last resort",
                    dir.path().display()
                ),
                "{kind}"
            );

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
                    assert_eq!(store_problem(dir.path()), None, "{kind}");
                }
                Fails::Counter => {
                    assert_eq!(counted, "Passkeys: room for 997 more", "{kind}");
                    assert!(
                        problem.what.ends_with(
                            "the key cannot sign in to sites that registered it as a security \
                             key and whose credentials it did not store"
                        ),
                        "{kind}: {problem:?}"
                    );
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
        let problem = store_problem(dir.path()).expect("a lost directory is a problem");
        assert!(
            problem
                .what
                .starts_with("the credential store is damaged (credentials is missing)"),
            "{problem:?}"
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
        assert_eq!(store_problem(dir.path()), None);
    }

    #[test]
    fn setup_asks_again_for_a_mistyped_pin() {
        let dir = TempDir::new("cli-first-pin");
        let (_daemon, mut key) = start(&dir);
        set_first_pin(&mut key, &mut Script::of(&["12", "1234"])).unwrap();
        assert!(key.management_token(b"1234").is_ok());

        let dir = TempDir::new("cli-first-pin-gives-up");
        let (_daemon, mut key) = start(&dir);
        let err = set_first_pin(&mut key, &mut Script::of(&["1", "2", "3", "4567"])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        assert_eq!(key.info().unwrap().pin_set, Some(false));
    }

    #[test]
    fn setup_pin_readiness_roundtrips_without_replacing_a_valid_pin() {
        let dir = TempDir::new("setup-pin-ready");
        let (_daemon, mut key) = start(&dir);
        assert!(ensure_pin_on(&mut key, false, &mut Script::of(&[])).is_err());
        assert_eq!(key.info().unwrap().pin_set, Some(false));
        ensure_pin_on(&mut key, true, &mut Script::of(&["1234"])).unwrap();
        let token = key.config_token(b"1234").unwrap();
        key.toggle_always_uv(Some(&token)).unwrap();
        ensure_pin_on(&mut key, false, &mut Script::of(&[])).unwrap();
        assert!(key.management_token(b"1234").is_ok());
        assert_eq!(key.info().unwrap().always_uv, Some(true));
    }

    #[test]
    fn setup_does_not_report_a_blocked_pin_as_ready() {
        let dir = TempDir::new("setup-blocked-pin");
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        for _ in 0..3 {
            assert!(key.management_token(b"0000").is_err());
        }
        let err = ensure_pin_on(&mut key, false, &mut Script::of(&[])).unwrap_err();
        assert!(
            err.to_string().contains("pqkey stop && pqkey start"),
            "{err}"
        );
        assert_eq!(key.info().unwrap().pin_set, Some(true));
    }

    #[test]
    fn setup_completes_a_required_pin_change_only_with_user_input() {
        let dir = TempDir::new("setup-forced-pin");
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        let token = key.config_token(b"1234").unwrap();
        key.set_min_pin_length(Some(&token), None, None, Some(true), None)
            .unwrap();
        assert!(ensure_pin_on(&mut key, false, &mut Script::of(&[])).is_err());
        assert_eq!(key.info().unwrap().force_pin_change, Some(true));
        ensure_pin_on(&mut key, true, &mut Script::of(&["1234", "5678"])).unwrap();
        assert_eq!(key.info().unwrap().force_pin_change, Some(false));
        assert!(key.management_token(b"5678").is_ok());
    }

    #[test]
    fn a_wrong_pin_reports_the_retries_left() {
        let dir = TempDir::new("cli-wrong-pin");
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        let err = set_or_change_pin(&mut key, &mut Script::of(&["0000", "5678"])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(err.to_string(), "wrong PIN; 7 retries left");

        // A PIN that could never have been set costs no retry.
        let err = set_or_change_pin(&mut key, &mut Script::of(&["12"])).unwrap_err();
        assert!(err.to_string().contains("no retry was used"), "{err}");
        assert_eq!(retries(&mut key), 7);
    }

    #[test]
    fn three_wrong_pins_in_a_row_ask_for_a_replug() {
        let dir = TempDir::new("cli-replug");
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        for _ in 0..2 {
            let err = management_token(&mut key, &mut Script::of(&["0000"])).unwrap_err();
            assert!(err.to_string().starts_with("wrong PIN"), "{err}");
        }
        let err = management_token(&mut key, &mut Script::of(&["0000"])).unwrap_err();
        assert!(err.to_string().contains(REPLUG), "{err}");
        // From now on no PIN is asked for: the script is empty.
        let err = management_token(&mut key, &mut Script::of(&[])).unwrap_err();
        assert!(err.to_string().contains(REPLUG), "{err}");
        let err = set_or_change_pin(&mut key, &mut Script::of(&[])).unwrap_err();
        assert!(err.to_string().contains(REPLUG), "{err}");
    }

    /// A PIN blocked by a PIN state the key could not read: `status` and the
    /// PIN commands say to restart the key before resetting it, which erases
    /// every passkey, and the restart does unblock the PIN.
    #[test]
    fn a_blocked_pin_is_restarted_before_it_is_reset() {
        let dir = TempDir::new("cli-blocked-restart");
        {
            let (_daemon, mut key) = start(&dir);
            key.set_pin(b"1234").unwrap();
            block_pin_until_restart(&dir, &mut key);
            let line = pin_state(key.pin_retries().unwrap());
            assert!(at(&line, REPLUG) < at(&line, "`pqkey reset`"), "{line}");
            assert!(line.contains("erases every passkey"), "{line}");
            // No PIN is asked for: the script is empty.
            for err in [
                management_token(&mut key, &mut Script::of(&[])).unwrap_err(),
                set_or_change_pin(&mut key, &mut Script::of(&[])).unwrap_err(),
            ] {
                let message = err.to_string();
                assert!(message.starts_with("the PIN is blocked"), "{message}");
                assert!(
                    at(&message, REPLUG) < at(&message, "`pqkey reset`"),
                    "{message}"
                );
                assert!(message.contains("erases every passkey"), "{message}");
            }
        }
        let (_daemon, mut key) = start(&dir);
        assert_eq!(retries(&mut key), 8);
        assert!(management_token(&mut key, &mut Script::of(&["1234"])).is_ok());
    }

    /// A PIN check that fails because the key cannot read its PIN state says
    /// so and names the log; it costs no retry, and the PIN works once the
    /// state can be read again.
    #[test]
    fn a_pin_state_the_key_cannot_read_points_at_the_log() {
        let dir = TempDir::new("cli-pin-state-unread");
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        let path = dir.path().join("pin-state");
        let stored = std::fs::read(&path).unwrap();
        // Reading a directory in its place fails with EISDIR, as root too.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let err = management_token(&mut key, &mut Script::of(&["1234"])).unwrap_err();
        assert_eq!(
            err.to_string(),
            "the key could not read or write its state; `journalctl --user -u pqkey` says why"
        );
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, stored).unwrap();
        assert_eq!(retries(&mut key), 8);
        assert!(management_token(&mut key, &mut Script::of(&["1234"])).is_ok());
    }

    #[test]
    fn passkeys_need_a_pin() {
        let dir = TempDir::new("cli-passkeys-no-pin");
        let (_daemon, mut key) = start(&dir);
        let err = management_token(&mut key, &mut Script::of(&[])).unwrap_err();
        assert!(err.to_string().contains("`pqkey pin` sets one"), "{err}");
    }

    #[test]
    fn a_passkey_is_deleted_by_part_of_its_name() {
        let dir = TempDir::new("cli-delete");
        {
            let mut store = FileStore::open(dir.path()).unwrap();
            for (rp, id, name) in [("example.com", 1, "alice"), ("example.com", 2, "bob")] {
                store
                    .put(&discoverable(rp, id, name, CoseAlg::MLDSA65))
                    .unwrap();
            }
        }
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        let token = management_token(&mut key, &mut Script::of(&["1234"])).unwrap();
        let passkeys = key.passkeys(&token).unwrap();
        let bob = matching_passkey(&passkeys, "BO").unwrap();
        key.delete(&token, &bob.credential_id).unwrap();
        let left = key.passkeys(&token).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].user_name.as_deref(), Some("alice"));
    }

    #[test]
    fn config_displays_defaults_and_toggles_without_a_pin() {
        let dir = TempDir::new("cli-config-no-pin");
        let (_daemon, mut key) = start(&dir);
        let mut no_confirmation = |_: &str| -> io::Result<bool> {
            panic!("this action must not ask for confirmation");
        };
        let lines = configure(&mut key, &mut Script::of(&[]), None, &mut no_confirmation).unwrap();
        assert_eq!(
            lines,
            [
                "Always UV: off",
                "Minimum PIN length: 4",
                "PIN complexity: off",
                "PIN change required: no",
            ]
        );
        assert!(policy_status(&key.info().unwrap()).is_empty());
        for setting in [
            super::super::AlwaysUv::Off,
            super::super::AlwaysUv::On,
            super::super::AlwaysUv::On,
            super::super::AlwaysUv::Off,
        ] {
            let action = ConfigAction::AlwaysUv { setting };
            let lines = configure(
                &mut key,
                &mut Script::of(&[]),
                Some(&action),
                &mut no_confirmation,
            )
            .unwrap();
            assert_eq!(
                lines[0],
                format!("Always UV: {}.", on_off(setting.enabled()))
            );
            assert!(lines[1].contains("`pqkey pin` sets one"), "{lines:?}");
            assert_eq!(key.info().unwrap().always_uv, Some(setting.enabled()));
        }
        let err = configure(
            &mut key,
            &mut Script::of(&[]),
            Some(&ConfigAction::ForcePinChange),
            &mut no_confirmation,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no PIN to change"), "{err}");
        assert!(err.to_string().contains("pqkey pin"), "{err}");
    }

    #[test]
    fn a_minimum_change_is_confirmed_before_reading_the_pin() {
        let dir = TempDir::new("cli-config-confirm");
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        let action = ConfigAction::MinPinLength {
            minimum: 6,
            rp_ids: Vec::new(),
            yes: false,
        };
        let mut questions = Vec::new();
        let lines = configure(
            &mut key,
            &mut Script::of(&[]),
            Some(&action),
            &mut |question| {
                questions.push(question.to_owned());
                Ok(false)
            },
        )
        .unwrap();
        assert_eq!(lines, ["Nothing was changed."]);
        assert_eq!(key.info().unwrap().min_pin_length, Some(4));
        assert_eq!(retries(&mut key), 8);
        assert_eq!(questions.len(), 1);
        assert!(questions[0].contains("Only a reset"), "{questions:?}");
        assert!(
            questions[0].contains("erases every passkey"),
            "{questions:?}"
        );
        assert!(questions[0].contains("large blob"), "{questions:?}");
        let lines = configure(
            &mut key,
            &mut Script::of(&["1234"]),
            Some(&action),
            &mut |_| Ok(true),
        )
        .unwrap();
        assert_eq!(
            lines,
            [
                "Minimum PIN length: 6.",
                "A PIN change is required; run `pqkey pin`."
            ]
        );
        assert_eq!(key.info().unwrap().min_pin_length, Some(6));
        assert_eq!(
            policy_status(&key.info().unwrap()),
            ["PIN change required; run `pqkey pin`"]
        );
        let err = management_token(&mut key, &mut Script::of(&["1234"])).unwrap_err();
        assert!(err.to_string().contains("PIN change"), "{err}");
        assert!(err.to_string().contains("pqkey pin"), "{err}");
        let err = set_or_change_pin(&mut key, &mut Script::of(&["1234", "12345"])).unwrap_err();
        assert_eq!(err.to_string(), "PIN must be at least 6 characters long");
        assert_eq!(retries(&mut key), 8);
        assert_eq!(
            set_or_change_pin(&mut key, &mut Script::of(&["1234", "123456"])).unwrap(),
            PinChange::Changed
        );
        assert!(management_token(&mut key, &mut Script::of(&["123456"])).is_ok());
    }

    #[test]
    fn minimum_changes_preserve_rps_when_omitted_and_report_capacity() {
        let dir = TempDir::new("cli-config-rps");
        let (_daemon, mut key) = start(&dir);
        let change = |minimum, rp_ids| ConfigAction::MinPinLength {
            minimum,
            rp_ids,
            yes: true,
        };
        let mut no_confirmation = |_: &str| -> io::Result<bool> {
            panic!("--yes must skip confirmation");
        };
        let action = change(6, vec!["example.com".into(), "other.example".into()]);
        assert_eq!(
            configure(
                &mut key,
                &mut Script::of(&[]),
                Some(&action),
                &mut no_confirmation
            )
            .unwrap(),
            ["Minimum PIN length: 6."]
        );
        let stored = || {
            FileStore::open(dir.path())
                .unwrap()
                .pin_state()
                .unwrap()
                .unwrap()
        };
        assert_eq!(
            stored().min_pin_length_rp_ids,
            ["example.com", "other.example"]
        );
        configure(
            &mut key,
            &mut Script::of(&[]),
            Some(&change(7, Vec::new())),
            &mut no_confirmation,
        )
        .unwrap();
        assert_eq!(
            stored().min_pin_length_rp_ids,
            ["example.com", "other.example"]
        );
        let unchanged = stored();
        let err = configure(
            &mut key,
            &mut Script::of(&[]),
            Some(&change(6, Vec::new())),
            &mut no_confirmation,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("cannot be lowered below 7"),
            "{err}"
        );
        assert!(err.to_string().contains("erases every passkey"), "{err}");
        assert!(err.to_string().contains("large blob"), "{err}");
        assert_eq!(stored(), unchanged);
        for rp_ids in [vec!["example.com".into(); 9], vec!["a".repeat(254)]] {
            let err = configure(
                &mut key,
                &mut Script::of(&[]),
                Some(&change(8, rp_ids)),
                &mut no_confirmation,
            )
            .unwrap_err();
            assert!(err.to_string().contains("at most 8 RP IDs"), "{err}");
            assert!(err.to_string().contains("at most 253 bytes"), "{err}");
            assert_eq!(stored(), unchanged);
        }
        let err = set_or_change_pin(&mut key, &mut Script::of(&["1234"])).unwrap_err();
        assert_eq!(err.to_string(), "PIN must be at least 7 characters long");
        set_first_pin(&mut key, &mut Script::of(&["123456", "1234567"])).unwrap();
        assert!(key.config_token(b"1234567").is_ok());
    }

    #[test]
    fn oversized_configuration_preserves_policy_and_a_shorter_eight_rp_list_succeeds() {
        for pin_set in [false, true] {
            let dir = TempDir::new("cli-config-size");
            let (_daemon, mut key) = start(&dir);
            if pin_set {
                key.set_pin(b"123456").unwrap();
            }
            let stored = || {
                FileStore::open(dir.path())
                    .unwrap()
                    .pin_state()
                    .unwrap()
                    .unwrap()
            };
            let original = ConfigAction::MinPinLength {
                minimum: 4,
                rp_ids: vec!["original.example".into()],
                yes: true,
            };
            let pins = if pin_set { &["123456"][..] } else { &[] };
            configure(
                &mut key,
                &mut Script::of(pins),
                Some(&original),
                &mut |_| Ok(true),
            )
            .unwrap();
            let unchanged = stored();
            let oversized = ConfigAction::MinPinLength {
                minimum: 6,
                rp_ids: (0..8)
                    .map(|index| format!("{index}{}", "x".repeat(252)))
                    .collect(),
                yes: true,
            };
            let error = configure(
                &mut key,
                &mut Script::of(pins),
                Some(&oversized),
                &mut |_| Ok(true),
            )
            .unwrap_err();
            let bytes = if pin_set { 2087 } else { 2050 };
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(
                error.to_string(),
                format!(
                    "the encoded CTAP2 request is {bytes} bytes; the limit is 1768 bytes; \
                 shorten the RP list (use fewer or shorter RP IDs)"
                )
            );
            assert_eq!(stored(), unchanged);
            assert_eq!(key.info().unwrap().max_msg_size, 1768);
            let rps: Vec<_> = (0..8)
                .map(|index| format!("{index}.short.example"))
                .collect();
            let smaller = ConfigAction::MinPinLength {
                minimum: 6,
                rp_ids: rps.clone(),
                yes: true,
            };
            configure(&mut key, &mut Script::of(pins), Some(&smaller), &mut |_| {
                Ok(true)
            })
            .unwrap();
            assert_eq!(stored().min_pin_length, 6);
            assert_eq!(stored().min_pin_length_rp_ids, rps);
            assert!(!stored().force_pin_change);
        }
    }

    #[test]
    fn forced_pin_change_refuses_reuse_and_explains_token_errors() {
        let dir = TempDir::new("cli-config-force");
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        let mut no_confirmation = |_: &str| -> io::Result<bool> {
            panic!("force-pin-change does not ask for confirmation");
        };
        assert_eq!(
            configure(
                &mut key,
                &mut Script::of(&["1234"]),
                Some(&ConfigAction::ForcePinChange),
                &mut no_confirmation
            )
            .unwrap(),
            ["A PIN change is required; run `pqkey pin`."]
        );
        let on = ConfigAction::AlwaysUv {
            setting: super::super::AlwaysUv::On,
        };
        let off = ConfigAction::AlwaysUv {
            setting: super::super::AlwaysUv::Off,
        };
        assert_eq!(
            configure(
                &mut key,
                &mut Script::of(&[]),
                Some(&off),
                &mut no_confirmation
            )
            .unwrap(),
            ["Always UV: off."]
        );
        let err = configure(
            &mut key,
            &mut Script::of(&["1234"]),
            Some(&on),
            &mut no_confirmation,
        )
        .unwrap_err();
        assert!(err.to_string().contains("run `pqkey pin`"), "{err}");
        let err = set_or_change_pin(&mut key, &mut Script::of(&["1234", "1234"])).unwrap_err();
        assert!(
            err.to_string().contains("must differ from the current PIN"),
            "{err}"
        );
        assert_eq!(key.info().unwrap().force_pin_change, Some(true));
        set_or_change_pin(&mut key, &mut Script::of(&["1234", "5678"])).unwrap();
        assert_eq!(key.info().unwrap().force_pin_change, Some(false));
        configure(
            &mut key,
            &mut Script::of(&["5678"]),
            Some(&on),
            &mut no_confirmation,
        )
        .unwrap();
        assert_eq!(
            policy_status(&key.info().unwrap()),
            ["Always UV: on; registrations and sign-ins require the PIN"]
        );
        assert_eq!(
            configure(
                &mut key,
                &mut Script::of(&[]),
                Some(&on),
                &mut no_confirmation
            )
            .unwrap(),
            ["Always UV: on."]
        );
    }

    #[test]
    fn config_displays_persisted_settings_after_a_restart() {
        let dir = TempDir::new("cli-config-restart");
        {
            let (_daemon, mut key) = start(&dir);
            key.set_min_pin_length(None, Some(6), None, None, None)
                .unwrap();
            key.set_pin(b"123456").unwrap();
            let token = key.config_token(b"123456").unwrap();
            key.toggle_always_uv(Some(&token)).unwrap();
            key.set_min_pin_length(Some(&token), None, None, Some(true), None)
                .unwrap();
        }
        let (_daemon, mut key) = start(&dir);
        let lines = configure(&mut key, &mut Script::of(&[]), None, &mut |_| {
            panic!("display must not ask for confirmation")
        })
        .unwrap();
        assert_eq!(
            lines,
            [
                "Always UV: on",
                "Minimum PIN length: 6",
                "PIN complexity: off",
                "PIN change required: yes"
            ]
        );
        assert_eq!(
            policy_status(&key.info().unwrap()),
            [
                "Always UV: on; registrations and sign-ins require the PIN",
                "PIN change required; run `pqkey pin`",
            ]
        );
    }

    #[test]
    fn a_no_pin_minimum_change_explains_always_uv_recovery() {
        let dir = TempDir::new("cli-config-no-pin-always-uv");
        let (_daemon, mut key) = start(&dir);
        key.toggle_always_uv(None).unwrap();
        let action = ConfigAction::MinPinLength {
            minimum: 6,
            rp_ids: Vec::new(),
            yes: true,
        };
        let err = configure(&mut key, &mut Script::of(&[]), Some(&action), &mut |_| {
            panic!("--yes must skip confirmation")
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("set one with `pqkey pin`"),
            "{err}"
        );
        assert!(
            err.to_string().contains("pqkey config always-uv off"),
            "{err}"
        );
        assert_eq!(key.info().unwrap().min_pin_length, Some(4));
    }

    fn passkey(rp_id: &str, name: Option<&str>, display: Option<&str>, id: u8) -> Passkey {
        Passkey {
            rp_id: rp_id.into(),
            user_id: vec![id],
            user_name: name.map(Into::into),
            user_display_name: display.map(Into::into),
            credential_id: [0x01].into_iter().chain([id; 32]).collect(),
            alg: Some(-49),
            third_party_payment: None,
        }
    }

    #[test]
    fn a_query_names_exactly_one_passkey() {
        let passkeys = [
            passkey("example.com", Some("alice"), Some("Alice A."), 0xaa),
            passkey("example.com", Some("bob"), None, 0xbb),
            passkey("other.example", Some("alice"), None, 0xcc),
        ];
        let user_of = |query| matching_passkey(&passkeys, query).map(|p| p.credential_id[1]);
        assert_eq!(user_of("bob").unwrap(), 0xbb);
        assert_eq!(user_of("OTHER").unwrap(), 0xcc);
        assert_eq!(user_of("alice a.").unwrap(), 0xaa);
        assert_eq!(user_of("01cccc").unwrap(), 0xcc);

        let err = user_of("alice").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("matches 2 passkeys"), "{err}");
        assert!(err.to_string().contains("other.example"), "{err}");
        assert_eq!(
            user_of("carol").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(user_of("").unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn payment_display_keeps_id_order_and_delete_matching() {
        let mut enabled = passkey("example.com", Some("alice"), None, 0x11);
        enabled.third_party_payment = Some(true);
        let mut disabled = passkey("example.com", Some("alice"), None, 0x22);
        disabled.third_party_payment = Some(false);
        let legacy = passkey("example.com", Some("alice"), None, 0x33);
        let passkeys = [legacy, disabled, enabled];
        let table = passkey_table(&passkeys);
        let rows: Vec<_> = table[1..]
            .iter()
            .map(|r| r.split_whitespace().collect::<Vec<_>>())
            .collect();
        assert_eq!(
            rows.iter().map(|r| (r[3], r[4])).collect::<Vec<_>>(),
            [
                ("enabled", "0111111111111111"),
                ("-", "0122222222222222"),
                ("-", "0133333333333333")
            ]
        );
        assert_eq!(
            matching_passkey(&passkeys, "011111")
                .unwrap()
                .third_party_payment,
            Some(true)
        );
        assert!(matching_passkey(&passkeys, "enabled").is_err());
    }

    #[test]
    fn the_table_is_aligned_sorted_and_safe_to_print() {
        let passkeys = [
            passkey("z.example", Some("zed"), Some("Zed"), 0x22),
            passkey(
                "evil.example",
                Some("a\u{1b}[2Jb\u{202e}c"),
                Some("Mallory"),
                0x11,
            ),
            passkey("a.example", None, None, 0x33),
        ];
        let table = passkey_table(&passkeys);
        assert_eq!(
            table,
            [
                "SITE          USER               ALGORITHM  PAYMENT  ID",
                "a.example     -                  ML-DSA-65  -        0133333333333333",
                "evil.example  a [2Jbc (Mallory)  ML-DSA-65  -        0111111111111111",
                "z.example     zed (Zed)          ML-DSA-65  -        0122222222222222",
            ]
        );
        for line in &table {
            assert!(!line.chars().any(char::is_control), "{line:?}");
        }
        for (alg, name) in [
            (-7, "ES256"),
            (-48, "ML-DSA-44"),
            (-49, "ML-DSA-65"),
            (-50, "ML-DSA-87"),
            (-9, "ESP256"),
            (-35, "ES384"),
            (-51, "ESP384"),
            (-36, "ES512"),
            (-52, "ESP512"),
            (-47, "ES256K"),
            (-8, "EdDSA"),
            (-19, "Ed25519"),
            (-53, "Ed448"),
            (-257, "RS256"),
            (-258, "RS384"),
            (-259, "RS512"),
            (-37, "PS256"),
            (-38, "PS384"),
            (-39, "PS512"),
            (-265, "ESB256"),
            (-267, "ESB384"),
        ] {
            assert_eq!(algorithm(Some(alg)), name);
        }
        assert_eq!(algorithm(Some(-65535)), "COSE -65535");
        assert_eq!(algorithm(None), "-");
    }

    #[test]
    fn an_empty_answer_takes_the_default() {
        assert!(is_yes("\n", true));
        assert!(!is_yes("\n", false));
        assert!(is_yes(" Yes\n", false));
        assert!(!is_yes("no\n", true));
        assert!(!is_yes("yep\n", true));
    }

    #[test]
    fn pin_and_reset_errors_name_the_fix() {
        let status = |code| pin_error_message(&ClientError::Status(code), None).to_string();
        assert!(status(CTAP2_ERR_PIN_AUTH_BLOCKED).contains(REPLUG));
        assert!(status(CTAP2_ERR_PIN_BLOCKED).contains("pqkey reset"));
        assert!(status(CTAP2_ERR_PIN_BLOCKED).contains("large blob"));
        assert!(status(CTAP2_ERR_PIN_NOT_SET).contains("pqkey pin"));
        let last = PinRetries {
            retries: 1,
            power_cycle_needed: false,
        };
        let message =
            pin_error_message(&ClientError::Status(CTAP2_ERR_PIN_INVALID), Some(last)).to_string();
        assert!(message.contains("1 retry left"), "{message}");
        for (code, says) in [
            (CTAP2_ERR_OPERATION_DENIED, "denied"),
            (CTAP2_ERR_USER_ACTION_TIMEOUT, "not approved in time"),
            (CTAP2_ERR_KEEPALIVE_CANCEL, "cancelled"),
            (CTAP2_ERR_NOT_ALLOWED, "within 10 seconds"),
        ] {
            let message = reset_error(ClientError::Status(code)).to_string();
            assert!(message.contains(says), "{code:#x}: {message}");
        }
        assert_eq!(
            pin_state(PinRetries {
                retries: 8,
                power_cycle_needed: false
            }),
            "set (8 retries left)"
        );

        // A blocked PIN: restart the key and look again, and only then reset
        // it, which erases the passkeys.
        let blocked = status(CTAP2_ERR_PIN_BLOCKED);
        let line = pin_state(PinRetries {
            retries: 0,
            power_cycle_needed: false,
        });
        assert!(line.starts_with("blocked; "), "{line}");
        assert!(
            at(&line, REPLUG) < at(&line, "`pqkey status` again"),
            "{line}"
        );
        assert!(blocked.contains("could not read or write its PIN state"));
        assert!(
            at(&blocked, REPLUG) < at(&blocked, "try again"),
            "{blocked}"
        );
        for advice in [&line, &blocked] {
            assert!(at(advice, REPLUG) < at(advice, "`pqkey reset`"), "{advice}");
            assert!(
                at(advice, "still blocked") < at(advice, "`pqkey reset`"),
                "{advice}"
            );
            assert!(
                advice.contains("erases every passkey and large blob"),
                "{advice}"
            );
        }

        // A key that could not read or write its state names the log, for
        // every command but setPIN, which says more.
        let processing =
            "the key could not read or write its state; `journalctl --user -u pqkey` says why";
        assert_eq!(status(CTAP2_ERR_PROCESSING), processing);
        assert_eq!(
            reset_error(ClientError::Status(CTAP2_ERR_PROCESSING)).to_string(),
            processing
        );
        assert_eq!(
            client_error(ClientError::Status(CTAP2_ERR_PROCESSING)).to_string(),
            processing
        );
    }

    /// A PIN blocked before `pqkey reset` restarts the key, and unblocked by
    /// the restart: the user is told and asked again.  Keeping the key erases
    /// nothing; resetting it anyway restarts the key once more, so that the
    /// reset comes within 10 seconds of its start however long the answer
    /// took.
    #[test]
    fn a_reset_asks_again_when_the_restart_unblocks_the_pin() {
        for answer in [false, true] {
            let dir = TempDir::new("cli-reset-unblocked");
            let (mut keys, key) = blocked_key(&dir);
            let (restarted, questions) = keys.reset(false, key, Some(answer));
            let [question] = &questions[..] else {
                panic!("{questions:?}");
            };
            assert!(
                question.starts_with("The PIN is no longer blocked now that the key has restarted"),
                "{question}"
            );
            assert!(
                at(question, "no longer blocked") < at(question, "Reset the key anyway?"),
                "{question}"
            );
            assert!(
                question.contains("passkeys, large blobs and PIN are erased"),
                "{question}"
            );
            if answer {
                assert_eq!(keys.restarts, 2);
                erase(restarted.expect("a key to reset"));
            } else {
                assert!(restarted.is_none());
                assert_eq!(keys.restarts, 1);
                nothing_erased(&mut keys);
            }
        }
    }

    /// A restarted key that cannot say whether its PIN is still blocked, as
    /// one that cannot read its PIN state: the user is asked again, with
    /// why, and keeping the key erases nothing.
    #[test]
    fn a_reset_asks_again_when_the_restarted_key_cannot_read_its_pin_state() {
        let dir = TempDir::new("cli-reset-unread");
        let (mut keys, key) = blocked_key(&dir);
        let path = dir.path().join("pin-state");
        let stored = std::fs::read(&path).unwrap();
        // Reading a directory in its place fails with EISDIR, as root too.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let (restarted, questions) = keys.reset(false, key, Some(false));
        assert!(restarted.is_none());
        let [question] = &questions[..] else {
            panic!("{questions:?}");
        };
        assert!(
            question.starts_with(
                "The key could not say after its restart whether the PIN is still blocked (the \
                 key could not read or write its state; `journalctl --user -u pqkey` says why). \
                 Reset the key anyway?"
            ),
            "{question}"
        );
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, stored).unwrap();
        nothing_erased(&mut keys);
    }

    /// `pqkey reset --yes` restarts the key and resets it as it always has,
    /// without looking at the PIN or asking, even where the restart unblocks
    /// the PIN.
    #[test]
    fn reset_yes_neither_looks_nor_asks() {
        let dir = TempDir::new("cli-reset-yes");
        let (mut keys, key) = blocked_key(&dir);
        let (restarted, _) = keys.reset(true, key, None);
        assert_eq!(keys.restarts, 1);
        erase(restarted.expect("a key to reset"));
    }

    /// A reset is asked about once where the restart does not unblock the
    /// PIN: one that works, or one that stays blocked.
    #[test]
    fn a_reset_asks_once_unless_the_restart_unblocks_the_pin() {
        for unreadable in [false, true] {
            let dir = TempDir::new("cli-reset-once");
            let (daemon, mut key) = start(&dir);
            key.set_pin(b"1234").unwrap();
            if unreadable {
                // A PIN state the key cannot read, before the restart and
                // after it.
                std::fs::write(dir.path().join("pin-state"), b"not a PIN state").unwrap();
            }
            assert_eq!(pin_blocked(&mut key).unwrap(), unreadable);
            let mut keys = Replugged::new(&dir, daemon);
            let (restarted, _) = keys.reset(false, key, None);
            assert_eq!(keys.restarts, 1);
            let mut key = restarted.expect("a key to reset");
            assert_eq!(pin_blocked(&mut key).unwrap(), unreadable);
            erase(key);
        }
    }
    #[test]
    fn complexity_confirmation_errors_normalization_restart_and_reset() {
        for existing in [false, true] {
            let dir = TempDir::new("cli-complexity");
            {
                let (_daemon, mut key) = start(&dir);
                if existing {
                    key.set_pin(b"1234").unwrap();
                }
                let action = ConfigAction::PinComplexity { yes: false };
                let lines = configure(
                    &mut key,
                    &mut Script::of(&[]),
                    Some(&action),
                    &mut |question| {
                        assert!(question.contains("ASCII letter"));
                        assert!(question.contains("ASCII digit"));
                        assert!(question.contains("Only a reset"));
                        assert!(question.contains("existing PIN must change"));
                        Ok(false)
                    },
                )
                .unwrap();
                assert_eq!(lines, ["Nothing was changed."]);
                assert_eq!(key.info().unwrap().pin_complexity_policy, Some(false));
                let pins = if existing { &["1234"][..] } else { &[][..] };
                configure(
                    &mut key,
                    &mut Script::of(pins),
                    Some(&ConfigAction::PinComplexity { yes: true }),
                    &mut |_| panic!("--yes"),
                )
                .unwrap();
                assert_eq!(key.info().unwrap().force_pin_change, Some(existing));
                configure(&mut key, &mut Script::of(&[]), Some(&action), &mut |_| {
                    panic!("already enabled")
                })
                .unwrap();
                let pins = if existing {
                    &["1234", "5678"][..]
                } else {
                    &["5678"][..]
                };
                let error = set_or_change_pin(&mut key, &mut Script::of(pins))
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("ASCII letter"), "{error}");
                assert!(error.contains("ASCII digit"), "{error}");
                assert!(!error.contains("5678"));
                // NFC turns e + acute into one non-ASCII letter: it is permitted,
                // but cannot satisfy the ASCII requirement by itself.
                let pins = if existing {
                    &["1234", "e\u{301}234"][..]
                } else {
                    &["e\u{301}234"][..]
                };
                assert!(
                    set_or_change_pin(&mut key, &mut Script::of(pins))
                        .unwrap_err()
                        .to_string()
                        .contains("ASCII letter")
                );
                let pins = if existing {
                    &["1234", "e\u{301}A12"][..]
                } else {
                    &["e\u{301}A12"][..]
                };
                set_or_change_pin(&mut key, &mut Script::of(pins)).unwrap();
                key.config_token("éA12".as_bytes()).unwrap();
            }
            let (_daemon, mut key) = start(&dir);
            assert_eq!(key.info().unwrap().pin_complexity_policy, Some(true));
            assert_eq!(key.info().unwrap().force_pin_change, Some(false));
            key.reset(&mut |_| {}).unwrap();
            assert_eq!(key.info().unwrap().pin_complexity_policy, Some(false));
            key.set_pin(b"1234").unwrap();
        }
    }
}
