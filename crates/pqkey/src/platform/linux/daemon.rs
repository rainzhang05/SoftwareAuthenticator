//! The systemd user service and Linux startup access warnings.
use super::permissions;
use crate::{
    cli::{checks::Problem, output::errln},
    platform::ServiceAction,
    state::path_error,
};
use nix::unistd::{self, Group, Pid};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
};

const UNIT: &str = "pqkey.service";
/// The systemd user unit this version ships, with `ExecStart` for
/// `/usr/local/bin/pqkey`.
pub(crate) const UNIT_TEMPLATE: &str =
    include_str!("../../../../../contrib/systemd/user/pqkey.service");
/// Units earlier versions shipped, which setup replaces as it does its own:
/// `contrib/systemd/user/pqkey.service` as of the commit each name gives, and
/// from 2026-10-05 until system calls were filtered. The README had users
/// install the first two by hand; setup wrote the others over any unit
/// until 9e91509 (2026-10-10), after which it keeps units it does not know.
/// Older units run `pqkey attach`, which pqkey no longer has, so
/// [`managed_unit`] keeps them as the user's own.
const EARLIER_UNITS: [&str; 6] = [
    include_str!("earlier-units/2026-10-01-341a669.service"),
    include_str!("earlier-units/2026-10-01-cf4da2d.service"),
    include_str!("earlier-units/2026-10-01-1fad615.service"),
    include_str!("earlier-units/2026-10-01-7be4862.service"),
    include_str!("earlier-units/2026-10-01-c591936.service"),
    include_str!("earlier-units/2026-10-05.service"),
];
/// The properties of the unit that [`UserService::problems`] reads.
const UNIT_STATE: &str = "LoadState,UnitFileState,ActiveState,SubState,Result,ExecMainStatus";
/// The fix for a service that failed. Its log says why, and `pqkey start`
/// resets the failed state before it starts the service, which systemd
/// refuses for a while without that once the service has been started too
/// often (`StartLimitBurst=`).
const FAILED_FIX: &str =
    "see why in `journalctl --user -u pqkey`, fix that, then run `pqkey start`";
/// The fix for a service that is not enabled where it is not known whether
/// the user's service manager lingers: with lingering, SECURITY.md advises
/// disabling the service, which `pqkey setup` would enable again.
const NOT_ENABLED_FIX: &str = "run `pqkey setup`; but if lingering is on (`loginctl \
    enable-linger`) and you disabled it as SECURITY.md advises, leave it and use `pqkey start`";
/// The fixes for a masked service. `unmask` removes a mask where setup
/// installs the unit, and setup installs it again, which also overrides a
/// mask elsewhere, and enables it. Where the user's service manager
/// lingers, SECURITY.md advises disabling it then; where that is not known,
/// the fix says so.
const MASKED_FIX: &str = "run `systemctl --user unmask pqkey`, then `pqkey setup`";
const MASKED_LINGERING_FIX: &str = "run `systemctl --user unmask pqkey`, then `pqkey setup`, \
    then `systemctl --user disable pqkey`, as SECURITY.md advises with lingering";
const MASKED_UNKNOWN_FIX: &str = "run `systemctl --user unmask pqkey`, then `pqkey setup`; but \
    if lingering is on (`loginctl enable-linger`), then also `systemctl --user disable pqkey`, \
    as SECURITY.md advises";

/// Where the user's systemd units live.
fn unit_dir() -> PathBuf {
    match env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".config"),
    }
    .join("systemd/user")
}

/// Whether systemd splits a command line such as `ExecStart=`'s at `c`,
/// outside quotes: at its WHITESPACE, ASCII space, tab, newline and
/// carriage return, and at no other white space, such as U+00A0 or U+3000
/// (`extract_first_word()`, which config_parse_exec() calls without
/// separators of its own).
fn splits_exec(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

/// The words systemd reads in `line`, a command line such as `ExecStart=`'s,
/// as config_parse_exec() splits it (`extract_first_word()` with
/// EXTRACT_UNQUOTE): a word ends at [`splits_exec`] outside quotes, and a
/// single or double quote anywhere in it keeps everything up to the
/// matching one in the word, and is removed. `None` for a quote left open,
/// and for a backslash, which starts a C escape that setup never writes.
fn exec_words(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.next_if(|&c| splits_exec(c)).is_some() {}
        if chars.peek().is_none() {
            return Some(words);
        }
        let mut word = String::new();
        let mut quote = None;
        for c in chars.by_ref() {
            match (quote, c) {
                (_, '\\') => return None,
                (Some(open), c) if c == open => quote = None,
                (None, '\'' | '"') => quote = Some(c),
                (None, c) if splits_exec(c) => break,
                (_, c) => word.push(c),
            }
        }
        if quote.is_some() {
            return None;
        }
        words.push(word);
    }
}

/// The unit, running `binary`.
pub(crate) fn unit_file(binary: &Path) -> io::Result<String> {
    let path = binary.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not valid UTF-8", binary.display()),
        )
    })?;
    // systemd refuses an executable whose name holds a quote, a backslash
    // or a control character, however it is quoted (`string_is_safe()`).
    if path
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | '\'' | '\\'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the unit cannot run {path:?}; install pqkey somewhere else"),
        ));
    }
    // systemd expands % specifiers in ExecStart, and splits it at white
    // space outside quotes ([`exec_words`]): a program with white space goes
    // in double quotes, in which nothing it may hold is special, so systemd
    // reads it back as written.
    let escaped = path.replace('%', "%%");
    let state = crate::state::default_state_dir();
    let state = state
        .to_str()
        .ok_or_else(|| io::Error::other("state path is not UTF-8"))?;
    if state
        .chars()
        .any(|c| c.is_control() || c == '"' || c == '\\')
    {
        return Err(io::Error::other(
            "unsupported state path for the user service",
        ));
    }
    // Quoting does not inhibit systemd's $ expansion in ExecStart.
    if escaped.contains('$') || state.contains('$') {
        return Err(io::Error::other("service paths must not contain '$'"));
    }
    let state = state.replace('%', "%%");
    let exec = if escaped.contains(splits_exec) {
        format!("ExecStart=\"{escaped}\" --state-dir \"{state}\" run")
    } else {
        format!("ExecStart={escaped} --state-dir \"{state}\" run")
    };
    let mut unit = String::with_capacity(UNIT_TEMPLATE.len() + exec.len());
    for line in UNIT_TEMPLATE.lines() {
        unit.push_str(if line.starts_with("ExecStart=") {
            &exec
        } else {
            line
        });
        unit.push('\n');
    }
    Ok(unit)
}

/// Install the unit for `binary` and have systemd read it, unless it is
/// installed as it is, or [`InstalledUnit::kept`]. Returns whether it changed.
fn install_unit(binary: &Path) -> io::Result<bool> {
    let unit = unit_file(binary)?;
    let dir = unit_dir();
    let path = dir.join(UNIT);
    let changed = match InstalledUnit::read(&path)? {
        // Keep custom arguments and policy, as `UserService::kept_unit` says.
        // Setup verifies the resulting daemon's identity and readiness rather
        // than replacing them. Never this version's unit: `managed_unit`
        // reads its `ExecStart=` back as written.
        Some(installed) if installed.kept() => false,
        // A prior write may have succeeded while daemon-reload failed.
        Some(installed) if installed.text == unit => false,
        _ => {
            write_unit(&dir, &path, &unit)?;
            true
        }
    };
    systemctl(&[
        "link",
        path.to_str()
            .ok_or_else(|| io::Error::other("unit path is not UTF-8"))?,
    ])?;
    drop(systemctl(&["daemon-reload"])?);
    Ok(changed)
}

/// Replace the unit file `path` in `dir` with `unit` as the credential store
/// replaces its files: through a new file in the same directory, flushed
/// before it is renamed into place, and the directory flushed after that, so
/// that a crash leaves either the old file or the whole new one, never an
/// empty one. A filesystem that cannot flush a directory counts as flushed,
/// as for the store. An error names the file or directory.
fn write_unit(dir: &Path, path: &Path, unit: &str) -> io::Result<()> {
    fs::create_dir_all(dir).map_err(|err| path_error(err, "create", dir))?;
    let temporary = dir.join(format!(".{UNIT}.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temporary)
        .map_err(|err| path_error(err, "create", &temporary))?;
    let written = file
        .write_all(unit.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, path));
    if let Err(err) = written {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(path_error(err, "write", path));
    }
    match fs::File::open(dir).and_then(|dir| dir.sync_all()) {
        Err(err)
            if !matches!(
                err.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
            ) =>
        {
            Err(path_error(err, "flush", dir))
        }
        _ => Ok(()),
    }
}

/// A unit file where setup installs the unit.
struct InstalledUnit {
    /// Its text, with any bytes that are not UTF-8 replaced.
    text: String,
    /// Whether it is a regular file that holds nothing but NUL bytes and
    /// white space, as a write that never reached the disk leaves it:
    /// nothing of the user's. systemd masks the unit for an empty file, and
    /// finds no `ExecStart=` in any other unless a drop-in has one.
    blank: bool,
}

impl InstalledUnit {
    /// The unit file at `path`, or `None` where there is none. Through a
    /// symbolic link it reads the target, but a link, as one to /dev/null,
    /// which masks the unit, is never blank: it is the user's to remove. An
    /// error names the file.
    fn read(path: &Path) -> io::Result<Option<Self>> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(path_error(err, "read", path)),
        };
        Ok(Some(Self {
            blank: bytes
                .iter()
                .all(|&byte| byte == 0 || byte.is_ascii_whitespace())
                && fs::symlink_metadata(path).is_ok_and(|file| file.is_file()),
            text: String::from_utf8_lossy(&bytes).into_owned(),
        }))
    }

    /// Whether setup keeps this unit as the user's own rather than replace
    /// it: one that is not [`managed_unit`] and not blank.
    fn kept(&self) -> bool {
        !self.blank && !managed_unit(&self.text)
    }
}

/// Only units matching the shipped template or one an earlier version
/// shipped, with the default state path, are rewritten. User drop-ins remain
/// under systemd's control.
fn managed_unit(unit: &str) -> bool {
    let without_exec = |text: &str| {
        text.lines()
            .filter(|line| !line.starts_with("ExecStart="))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let default_state = crate::state::default_state_dir();
    let default_state = default_state.to_str().map(|path| path.replace('%', "%%"));
    let exec = unit
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart="));
    // The words systemd runs: a program and `run`, with the default state
    // directory or none, as setup writes them.
    let ordinary_exec = exec
        .and_then(exec_words)
        .is_some_and(|words| match words.as_slice() {
            [_program, run] => run == "run",
            [_program, option, state, run] => {
                option == "--state-dir"
                    && default_state.as_deref() == Some(state.as_str())
                    && run == "run"
            }
            _ => false,
        });
    // Setup used to write a program with a single quote in its path as it
    // is, a line systemd cannot read ("Unbalanced quoting"); now it refuses
    // such a program, as systemd refuses a quote in an executable's name.
    // Such a line is setup's too.
    let unquoted_by_earlier_setup =
        exec.and_then(|exec| exec.strip_suffix(" run"))
            .is_some_and(|exec| {
                let (program, state) = match exec.split_once(" --state-dir ") {
                    Some((program, state)) => (program, Some(state)),
                    None => (exec, None),
                };
                program.contains('\'')
                    && !program.contains(|c| splits_exec(c) || c == '"' || c == '\\')
                    && state.is_none_or(|state| {
                        default_state
                            .as_deref()
                            .is_some_and(|default| state == format!("\"{default}\""))
                    })
            });
    let body = without_exec(unit);
    (ordinary_exec || unquoted_by_earlier_setup)
        && std::iter::once(UNIT_TEMPLATE)
            .chain(EARLIER_UNITS)
            .any(|template| without_exec(template) == body)
}

/// Run `systemctl --user` with `args`, failing with its message.
pub fn systemctl(args: &[&str]) -> io::Result<String> {
    let output = ProcessCommand::new("systemctl")
        // The user manager is on its standard runtime bus; notifications
        // may use a distinct desktop/test session bus.
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .arg("--user")
        .args(args)
        .stdin(Stdio::null())
        .output().map_err(|err| io::Error::new(err.kind(), format!(
            "cannot run systemctl --user: {err}; setup needs a working systemd user manager in your desktop session"
        )))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    } else {
        Err(io::Error::other(format!(
            "systemctl --user {} failed: {}; check your systemd user session and `journalctl --user -u pqkey`",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// A value as `systemctl --user show-environment` prints it: as it is, or,
/// where a shell would read it otherwise, as one with `;` or a space, quoted
/// as `$'…'`, with `\` and `'` escaped by a backslash and control characters
/// as C escapes (systemd 249, 252 and 255).
fn shown_value(shown: &str) -> String {
    let Some(quoted) = shown
        .strip_prefix("$'")
        .and_then(|rest| rest.strip_suffix('\''))
    else {
        return shown.to_owned();
    };
    let mut value = Vec::with_capacity(quoted.len());
    let mut bytes = quoted.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'\\' {
            value.push(byte);
            continue;
        }
        value.push(match bytes.next().unwrap_or(b'\\') {
            b'a' => 0x07,
            b'b' => 0x08,
            b't' => b'\t',
            b'n' => b'\n',
            b'v' => 0x0b,
            b'f' => 0x0c,
            b'r' => b'\r',
            // Three octal digits.
            first @ b'0'..=b'7' => bytes.by_ref().take(2).fold(first - b'0', |byte, digit| {
                byte.wrapping_mul(8).wrapping_add(digit.wrapping_sub(b'0'))
            }),
            // `\\` and `\'`.
            escaped => escaped,
        });
    }
    String::from_utf8_lossy(&value).into_owned()
}

/// Whether systemd-logind keeps the user's service manager running from
/// boot and after logout (`loginctl enable-linger`), as its `Linger`
/// property says. `None` where it cannot say, as for a user it does not
/// know: one who has no session and does not linger.
fn lingering() -> Option<bool> {
    let output = ProcessCommand::new("loginctl")
        .args([
            "show-user",
            &unistd::getuid().to_string(),
            "--property=Linger",
            "--value",
        ])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    match String::from_utf8_lossy(&output.stdout).trim() {
        "yes" if output.status.success() => Some(true),
        "no" if output.status.success() => Some(false),
        _ => None,
    }
}

pub(crate) fn warn_device_access() {
    if unistd::geteuid().is_root() {
        return;
    }
    match permissions::check_uhid_access() {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => warn_group_membership(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            errln!("warning: /dev/uhid is not available; run `pqkey setup`");
        }
        Err(_) => {}
    }
}

fn warn_group_membership() {
    const GROUP_NAME: &str = "plugdev";
    let plugdev_gid = Group::from_name(GROUP_NAME).ok().flatten().map(|g| g.gid);
    let groups = unistd::getgroups().unwrap_or_default();
    let in_group = plugdev_gid.is_some_and(|gid| groups.contains(&gid) || unistd::getegid() == gid);
    if in_group {
        errln!(
            "warning: cannot open /dev/uhid although you are in '{GROUP_NAME}'; run `pqkey setup`"
        );
    } else {
        errln!(
            "warning: cannot open /dev/uhid: you are not in '{GROUP_NAME}' yet, or have not \
             logged in again since you joined it; run `pqkey setup`"
        );
    }
}

/// The user's installed service. Operations retain systemctl's errors.
pub struct UserService;
impl UserService {
    pub const DESCRIPTION: &str = "systemd user service pqkey.service";
    pub const LOG_HINT: &str = "`journalctl --user -u pqkey.service`";
    // Discovery also serves manually started keys on hosts without a user
    // manager. Setup's install/action calls and final service checks retain
    // errors; a failed discovery must not disable the manual CLI workflow.
    pub fn installed() -> io::Result<bool> {
        Ok(
            systemctl(&["show", "--property", "LoadState", "--value", UNIT])
                .is_ok_and(|state| state == "loaded"),
        )
    }
    pub fn main_pid() -> io::Result<Option<Pid>> {
        Ok(
            systemctl(&["show", "--property", "MainPID", "--value", UNIT])
                .ok()
                .and_then(|pid| pid.parse::<i32>().ok())
                .filter(|pid| *pid > 0)
                .map(Pid::from_raw),
        )
    }
    /// This shell's session bus, the address in its DBUS_SESSION_BUS_ADDRESS,
    /// unless that is a bus over TCP, which the service cannot use: its unit
    /// allows it only Unix sockets.
    fn shell_bus() -> io::Result<Option<String>> {
        let Some(address) = env::var_os("DBUS_SESSION_BUS_ADDRESS") else {
            return Ok(None);
        };
        let address = address
            .into_string()
            .map_err(|_| io::Error::other("session bus address is not UTF-8"))?;
        Ok((!super::dbus::is_tcp_address(&address)).then_some(address))
    }

    /// The DBUS_SESSION_BUS_ADDRESS in the user manager's environment block,
    /// which the services it starts inherit, if it has one.
    fn given_bus() -> io::Result<Option<String>> {
        Ok(systemctl(&["show-environment"])?
            .lines()
            .find_map(|line| line.strip_prefix("DBUS_SESSION_BUS_ADDRESS="))
            .map(shown_value))
    }

    /// The session bus a service started with the bus `given` uses: that one,
    /// or without one the per-user bus, unless it is a bus over TCP, which
    /// the service cannot use.
    fn service_bus_of(given: Option<String>) -> Option<String> {
        let bus = super::dbus::session_bus_address(given.as_deref().map(std::ffi::OsStr::new));
        (!super::dbus::is_tcp_address(&bus)).then_some(bus)
    }

    /// The session bus the user manager gives the services it starts, the
    /// daemon among them, unless that is a bus over TCP.
    pub fn service_bus() -> io::Result<Option<String>> {
        Ok(Self::service_bus_of(Self::given_bus()?))
    }

    /// Have the user manager give the services it starts, the daemon among
    /// them, this shell's session bus, if it does not yet and `can_ask` finds
    /// a notification server there that can ask for approval. A bus that
    /// fails that check, as one left over from an earlier login, is not
    /// handed on: every user service started afterwards would inherit it.
    /// Returns the bus services get now, as [`Self::service_bus`] says.
    pub fn prepare_session(can_ask: impl FnOnce(&str) -> bool) -> io::Result<Option<String>> {
        let shell = Self::shell_bus()?;
        let given = Self::given_bus()?;
        if let Some(address) = shell
            && given.as_deref() != Some(address.as_str())
            && can_ask(&address)
        {
            systemctl(&[
                "set-environment",
                &format!("DBUS_SESSION_BUS_ADDRESS={address}"),
            ])?;
            return Ok(Some(address));
        }
        Ok(Self::service_bus_of(given))
    }
    pub fn action(action: ServiceAction) -> io::Result<()> {
        let action = match action {
            ServiceAction::Start => "start",
            ServiceAction::Restart => "restart",
            ServiceAction::Stop => "stop",
            ServiceAction::Enable => "enable",
            ServiceAction::ResetFailed => "reset-failed",
        };
        systemctl(&[action, UNIT]).map(drop)
    }
    pub fn install(binary: &Path) -> io::Result<bool> {
        install_unit(binary)
    }
    pub fn remove() -> io::Result<Option<PathBuf>> {
        let path = unit_dir().join(UNIT);
        if !path.exists() {
            return Ok(None);
        }
        let _ = systemctl(&["disable", UNIT]);
        fs::remove_file(&path)?;
        drop(systemctl(&["daemon-reload"])?);
        Ok(Some(path))
    }
    /// What status and setup say of the unit file where setup installs the
    /// unit, if setup keeps it as the user's own ([`InstalledUnit::kept`]):
    /// a regular file, or a link to one, but no mask. One that cannot be
    /// read is left to systemd's report.
    pub(crate) fn kept_unit() -> Option<Problem> {
        let path = unit_dir().join(UNIT);
        let kept = fs::metadata(&path).is_ok_and(|file| file.is_file())
            && InstalledUnit::read(&path).is_ok_and(|unit| unit.is_some_and(|unit| unit.kept()));
        kept.then(|| {
            Problem::new(
                format!(
                    "pqkey setup keeps your own unit {} as it is, instead of the unit this \
                     version installs",
                    path.display()
                ),
                format!(
                    "if you need its changes, put them in a drop-in with `systemctl --user edit \
                     pqkey`; then delete {} and run `pqkey setup`",
                    path.display()
                ),
            )
        })
    }
    pub(crate) fn manual_start_problem(pid: Pid) -> io::Result<Problem> {
        Ok(Problem {
            what: format!(
                "the key (pid {pid}) was started by hand, so the systemd user service cannot run it"
            ),
            fix: "run `pqkey stop && pqkey start`".into(),
        })
    }
    /// What keeps the service from starting the key with the session, or
    /// from running it, as `systemctl --user show` reports its unit: not
    /// installed, or not found where setup installed it, masked, or not
    /// enabled unless the user's service manager lingers, and, while the key
    /// does not run, failed, or failed and about to be restarted. A key
    /// started by hand has [`Self::manual_start_problem`] instead of the
    /// service's failure.
    pub(crate) fn problems(running: bool) -> io::Result<Vec<Problem>> {
        // As for `installed`, a query that fails finds no service.
        let shown = systemctl(&["show", "--property", UNIT_STATE, UNIT]).unwrap_or_default();
        let property = |name: &str| {
            shown
                .lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
                .unwrap_or_default()
        };
        let not_with_session = "so the key does not start with your session";
        match property("LoadState") {
            "loaded" => {}
            // An empty unit file, or a link to /dev/null. Where setup
            // installs the unit, it cannot enable it until `unmask` has
            // removed that file; its own unit there overrides a mask
            // elsewhere.
            "masked" => {
                let fix = match lingering() {
                    Some(false) => MASKED_FIX,
                    Some(true) => MASKED_LINGERING_FIX,
                    None => MASKED_UNKNOWN_FIX,
                };
                return Ok(vec![Problem::new(
                    format!("the {} is masked, {not_with_session}", Self::DESCRIPTION),
                    fix,
                )]);
            }
            // Not installed, or not where systemd looks. A unit file where
            // setup installs it that systemd does not find is not linked from
            // systemd's own directory: setup links it there, and SECURITY.md's
            // `systemctl --user disable pqkey` removes that link too. Linking
            // it again gives a unit that `pqkey start` starts and that is not
            // enabled, as SECURITY.md advises where the user lingers.
            load => {
                let not_started = "the key does not start with your session";
                let path = unit_dir().join(UNIT);
                if load != "not-found"
                    || !fs::symlink_metadata(&path).is_ok_and(|file| file.is_file())
                {
                    return Ok(vec![Problem::new(not_started, "run `pqkey setup`")]);
                }
                let link = format!(
                    "`systemctl --user link {}`",
                    super::setup::shell_quote(&path.to_string_lossy())
                );
                return Ok(vec![match lingering() {
                    Some(false) => Problem::new(not_started, "run `pqkey setup`"),
                    Some(true) => Problem::new(
                        format!(
                            "the {} is not found, so `pqkey start` starts the key by hand \
                             instead of through it",
                            Self::DESCRIPTION
                        ),
                        format!(
                            "run {link}, which does not enable it, as SECURITY.md advises with \
                             lingering"
                        ),
                    ),
                    None => Problem::new(
                        not_started,
                        format!(
                            "run `pqkey setup`; but if lingering is on (`loginctl enable-linger`) \
                             and you disabled it as SECURITY.md advises, run {link} instead"
                        ),
                    ),
                }]);
            }
        }
        let mut problems = Vec::new();
        if matches!(
            property("UnitFileState"),
            "disabled" | "linked" | "linked-runtime"
        ) {
            let not_enabled = format!(
                "the {} is not enabled, {not_with_session}",
                Self::DESCRIPTION
            );
            match lingering() {
                // What SECURITY.md advises where the service manager
                // lingers, so that the key does not start at boot, before
                // its user logs in; `pqkey start` starts it.
                Some(true) => {}
                Some(false) => problems.push(Problem::new(not_enabled, "run `pqkey setup`")),
                None => problems.push(Problem::new(not_enabled, NOT_ENABLED_FIX)),
            }
        }
        if running {
            return Ok(problems);
        }
        let failed = match (property("Result"), property("ExecMainStatus")) {
            ("exit-code", status) => format!("failed: the key exited with status {status}"),
            ("signal" | "core-dump", signal) => {
                format!("failed: the key was killed by signal {signal}")
            }
            (result, _) => format!("failed with result '{result}'"),
        };
        match (property("ActiveState"), property("SubState")) {
            ("failed", _) => problems.push(Problem::new(
                format!("the {} {failed}", Self::DESCRIPTION),
                FAILED_FIX,
            )),
            // Waiting for RestartSec= to pass, or for the restart's job.
            ("activating", state) if state.starts_with("auto-restart") => {
                problems.push(Problem::new(
                    format!(
                        "the {} {failed}; systemd is restarting it",
                        Self::DESCRIPTION
                    ),
                    FAILED_FIX,
                ));
            }
            _ => {}
        }
        Ok(problems)
    }
}

pub(crate) const START_HELP: &str =
    "Plug the key in: start it, through its systemd user service when that is installed";
pub(crate) const RUN_HELP: &str =
    "Run the key in the foreground until it is stopped (for the systemd unit and test rigs)";
pub(crate) const PRESENCE_NOTIFY_HELP: &str = "Ask with a desktop notification that has Approve \
    and Deny buttons. Without a session bus and a notification server that can show buttons, \
    every request is denied";

#[cfg(test)]
mod setup_tests {
    use super::*;
    #[test]
    fn service_install_child() {
        if env::var_os("PQKEY_SERVICE_CHILD").is_none() {
            return;
        }
        let result = (|| {
            if env::var_os("PQKEY_MANUAL_PROBE").is_some() {
                assert!(!UserService::installed()?);
                assert!(UserService::main_pid()?.is_none());
                return Ok(());
            }
            let binary = env::var_os("PQKEY_SERVICE_BINARY")
                .map_or_else(|| PathBuf::from("/usr/local/bin/pqkey"), PathBuf::from);
            let changed = UserService::install(&binary)?;
            println!("CHANGED:{changed}");
            if let Some(kept) = UserService::kept_unit() {
                println!("KEPT:{}\t{}", kept.what, kept.fix);
            }
            // A bus that passes setup's check; cli::setup's tests check it.
            UserService::prepare_session(|_| true)?;
            UserService::action(ServiceAction::Enable)
        })();
        if let Err(err) = &result {
            eprintln!("{err}");
        }
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }

    #[test]
    fn service_install_repairs_reload_and_preserves_custom_configuration() {
        use crate::test_support::TempDir;
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("setup-service-process");
        let bin = dir.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let script = bin.join("systemctl");
        fs::write(
            &script,
            r#"#!/bin/sh
printf '%s:%s\n' "$*" "${DBUS_SESSION_BUS_ADDRESS-unset}" >> "$COMMAND_TRACE"
if [ "${FAIL_ACTION-}" = "$2" ]; then echo "fixture $2 failed" >&2; exit 17; fi
exit 0
"#,
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let trace = dir.path().join("trace");
        let config = dir.path().join("config");
        let unit = config.join("systemd/user/pqkey.service");
        let child = |failure: &str| {
            ProcessCommand::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::linux::daemon::setup_tests::service_install_child",
                    "--nocapture",
                ])
                .env("PQKEY_SERVICE_CHILD", "1")
                .env("PATH", &bin)
                .env("XDG_CONFIG_HOME", &config)
                .env("XDG_DATA_HOME", dir.path().join("data space%"))
                .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/fixture/bus")
                .env("COMMAND_TRACE", &trace)
                .env("FAIL_ACTION", failure)
                .output()
                .unwrap()
        };
        let failed = child("daemon-reload");
        assert_eq!(failed.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&failed.stderr).contains("daemon-reload failed"));
        assert!(unit.exists(), "the first write succeeded, reload did not");
        let repaired = child("");
        assert!(repaired.status.success(), "{repaired:?}");
        assert!(String::from_utf8_lossy(&repaired.stdout).contains("CHANGED:false"));
        assert!(!String::from_utf8_lossy(&repaired.stdout).contains("KEPT:"));
        let commands = fs::read_to_string(&trace).unwrap();
        assert!(commands.contains("--user link"));
        assert!(commands.contains(
            "--user set-environment DBUS_SESSION_BUS_ADDRESS=unix:path=/fixture/bus:unset"
        ));
        assert!(commands.contains("--user enable pqkey.service:unset"));
        let managed = fs::read_to_string(&unit).unwrap();
        // Setup replaces `installed` with this version's unit, and names
        // nothing, or keeps it and names it.
        let replaced = |installed: &[u8], context: &str| {
            fs::write(&unit, installed).unwrap();
            let output = child("");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "{context}: {output:?}");
            assert!(stdout.contains("CHANGED:true"), "{context}: {stdout}");
            assert!(!stdout.contains("KEPT:"), "{context}: {stdout}");
            assert_eq!(fs::read_to_string(&unit).unwrap(), managed, "{context}");
        };
        let kept_unit = format!(
            "KEPT:pqkey setup keeps your own unit {0} as it is, instead of the unit this \
             version installs\tif you need its changes, put them in a drop-in with \
             `systemctl --user edit pqkey`; then delete {0} and run `pqkey setup`\n",
            unit.display()
        );
        let kept = |installed: &[u8], context: &str| {
            fs::write(&unit, installed).unwrap();
            let output = child("");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "{context}: {output:?}");
            assert!(stdout.contains("CHANGED:false"), "{context}: {stdout}");
            assert!(stdout.contains(&kept_unit), "{context}: {stdout}");
            assert_eq!(fs::read(&unit).unwrap(), installed, "{context}");
        };
        // An update replaces every unit an earlier version installed, the
        // one setup wrote from 2026-10-01 (c591936) among them: with
        // `ExecStart=` as setup writes it now, as setup wrote it before it
        // named the state directory, and as shipped, which the README and the
        // unit's comments had users install by hand.
        let exec = managed
            .lines()
            .find(|line| line.starts_with("ExecStart="))
            .unwrap();
        assert!(EARLIER_UNITS.contains(&include_str!("earlier-units/2026-10-01-c591936.service")));
        for (index, earlier) in EARLIER_UNITS.into_iter().enumerate() {
            for exec in [exec, "ExecStart=/usr/local/bin/pqkey run"] {
                let installed: String = earlier
                    .lines()
                    .map(|line| {
                        if line.starts_with("ExecStart=") {
                            exec
                        } else {
                            line
                        }
                    })
                    .flat_map(|line| [line, "\n"])
                    .collect();
                replaced(
                    installed.as_bytes(),
                    &format!("EARLIER_UNITS[{index}], {exec}"),
                );
            }
            replaced(
                earlier.as_bytes(),
                &format!("EARLIER_UNITS[{index}] as shipped"),
            );
        }
        // What a write that never reached the disk leaves: nothing, NUL
        // bytes, white space.
        for (blank, context) in [
            (&b""[..], "an empty file"),
            (&[0; 3647][..], "3647 NUL bytes"),
            (&b"\n  \t\r\n"[..], "white space"),
        ] {
            replaced(blank, context);
        }
        // A link there, as to /dev/null, which masks the unit, stays: it is
        // the user's to remove, and `systemctl --user unmask pqkey` does.
        fs::remove_file(&unit).unwrap();
        std::os::unix::fs::symlink("/dev/null", &unit).unwrap();
        let masked = child("");
        assert!(masked.status.success(), "{masked:?}");
        assert!(String::from_utf8_lossy(&masked.stdout).contains("CHANGED:false"));
        assert!(!String::from_utf8_lossy(&masked.stdout).contains("KEPT:"));
        assert_eq!(fs::read_link(&unit).unwrap(), Path::new("/dev/null"));
        fs::remove_file(&unit).unwrap();
        // No temporary file is left behind.
        replaced(b"", "after the link");
        assert_eq!(fs::read_dir(unit.parent().unwrap()).unwrap().count(), 1);
        let custom_state = UNIT_TEMPLATE.replace(
            "ExecStart=/usr/local/bin/pqkey run",
            "ExecStart=/usr/local/bin/pqkey --state-dir \"/retained/custom state\" run",
        );
        kept(custom_state.as_bytes(), "custom state");
        // An edited copy of this version's unit, and one that is not UTF-8.
        kept(
            format!("# my unit\n{managed}").as_bytes(),
            "an edited copy of this version's unit",
        );
        kept(
            &[&b"# caf\xe9\n"[..], managed.as_bytes()].concat(),
            "a unit that is not UTF-8",
        );
        let custom = managed.replace(" run\n", " run --presence unanswered\n");
        kept(custom.as_bytes(), "custom options");
        for action in ["link", "enable", "set-environment"] {
            assert_eq!(child(action).status.code(), Some(1), "{action}");
            assert_eq!(fs::read_to_string(&unit).unwrap(), custom);
        }
        // A unit file setup cannot read is named.
        fs::remove_file(&unit).unwrap();
        fs::create_dir(&unit).unwrap();
        let unreadable = child("");
        assert_eq!(unreadable.status.code(), Some(1), "{unreadable:?}");
        assert!(
            String::from_utf8_lossy(&unreadable.stderr)
                .contains(&format!("cannot read {}: ", unit.display())),
            "{unreadable:?}"
        );
        let probe = ProcessCommand::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "platform::linux::daemon::setup_tests::service_install_child",
                "--nocapture",
            ])
            .env("PQKEY_SERVICE_CHILD", "1")
            .env("PQKEY_MANUAL_PROBE", "1")
            .env("PATH", &bin)
            .env("XDG_DATA_HOME", dir.path().join("manual"))
            .env("COMMAND_TRACE", &trace)
            .env("FAIL_ACTION", "show")
            .output()
            .unwrap();
        assert!(probe.status.success(), "{probe:?}");
    }

    /// `service_install_child` for `binary` in `dir`, whose `config` is the
    /// user's configuration directory, with a systemctl that succeeds and,
    /// with `limited`, files limited to one block (`ulimit -f 1`) and
    /// SIGXFSZ ignored, so that writing the unit fails with EFBIG.
    fn install_in(dir: &Path, binary: &str, limited: bool) -> std::process::Output {
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("systemctl"), "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(bin.join("systemctl"), fs::Permissions::from_mode(0o755)).unwrap();
        let mut child = ProcessCommand::new("/bin/sh");
        child
            .arg("-c")
            .arg(if limited {
                "trap '' XFSZ; ulimit -f 1; exec \"$0\" \"$@\""
            } else {
                "exec \"$0\" \"$@\""
            })
            .arg(env::current_exe().unwrap())
            .args([
                "--exact",
                "platform::linux::daemon::setup_tests::service_install_child",
                "--nocapture",
            ])
            .env("PQKEY_SERVICE_CHILD", "1")
            .env("PQKEY_SERVICE_BINARY", binary)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("XDG_CONFIG_HOME", dir.join("config"))
            .env("XDG_DATA_HOME", dir.join("data"))
            .env_remove("DBUS_SESSION_BUS_ADDRESS");
        if limited {
            // Built for coverage, the child writes its profile as it exits,
            // under the same limit: that truncated profile goes here, not
            // where cargo llvm-cov merges every profile and fails on it.
            child.env("LLVM_PROFILE_FILE", dir.join("limited.profraw"));
        }
        child.output().unwrap()
    }

    /// A program whose path holds white space other than ASCII's, which
    /// systemd does not split at, such as U+00A0 or U+3000, or an ASCII space,
    /// which it does, gets this version's unit, and setup neither rewrites it
    /// on the next run nor names it as the user's.
    #[test]
    fn a_program_under_unusual_white_space_gets_its_unit_without_the_kept_line() {
        use crate::test_support::TempDir;
        for program in [
            "/opt/a\u{a0}b/pqkey",
            "/home/x\u{3000}y/pqkey",
            "/opt/a b/pqkey",
        ] {
            let dir = TempDir::new("service-unusual-path");
            for changed in ["CHANGED:true", "CHANGED:false"] {
                let output = install_in(dir.path(), program, false);
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(output.status.success(), "{program:?}: {output:?}");
                assert!(stdout.contains(changed), "{program:?}: {stdout}");
                assert!(!stdout.contains("KEPT:"), "{program:?}: {stdout}");
            }
            let unit =
                fs::read_to_string(dir.path().join("config/systemd/user/pqkey.service")).unwrap();
            assert_eq!(unit, unit_file_in(dir.path(), program), "{program:?}");
        }
    }

    /// This version's unit for `program` where the user's data directory
    /// (XDG_DATA_HOME) is `dir/data`, as `install_in` writes it.
    fn unit_file_in(dir: &Path, program: &str) -> String {
        let state = dir.join("data/pqkey").to_str().unwrap().replace('%', "%%");
        let exec = if program.contains(' ') {
            format!("\"{program}\"")
        } else {
            program.to_owned()
        };
        UNIT_TEMPLATE
            .lines()
            .map(|line| {
                if line.starts_with("ExecStart=") {
                    format!("ExecStart={exec} --state-dir \"{state}\" run\n")
                } else {
                    format!("{line}\n")
                }
            })
            .collect()
    }

    /// A unit write that fails, as when the file would grow past the limit
    /// on file sizes, is named with the unit file, and leaves neither its
    /// temporary file nor a unit behind.
    #[test]
    fn a_failed_unit_write_is_named_and_leaves_no_temporary_file() {
        use crate::test_support::TempDir;
        let dir = TempDir::new("service-write-fails");
        let unit = dir.path().join("config/systemd/user/pqkey.service");
        let output = install_in(dir.path(), "/usr/local/bin/pqkey", true);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(
            stderr.contains(&format!("cannot write {}: File too large", unit.display())),
            "{stderr}"
        );
        let left: Vec<_> = fs::read_dir(unit.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn custom_units_are_preserved_and_managed_units_are_upgradable() {
        assert!(managed_unit(UNIT_TEMPLATE));
        let old = UNIT_TEMPLATE.replace(
            "ExecStart=/usr/local/bin/pqkey run",
            "ExecStart=/home/a/.cargo/bin/pqkey run",
        );
        assert!(managed_unit(&old));
        assert!(!managed_unit(
            &old.replace("pqkey run", "pqkey run --presence unanswered")
        ));
        assert!(!managed_unit(
            &old.replace("pqkey run", "pqkey --presence unanswered run")
        ));
        assert!(!managed_unit(&format!("{old}\nEnvironment=CUSTOM=yes\n")));
        assert!(!managed_unit(
            &old.replace("Restart=on-failure", "Restart=no")
        ));
        for earlier in EARLIER_UNITS {
            assert!(!earlier.contains("\nSystemCallFilter="));
            assert!(managed_unit(earlier));
            assert!(!managed_unit(&format!(
                "{earlier}\nEnvironment=CUSTOM=yes\n"
            )));
        }
        // The units before 2026-10-01 run `pqkey attach --foreground`.
        assert!(!managed_unit(&old.replace(
            "ExecStart=/home/a/.cargo/bin/pqkey run",
            "ExecStart=%h/.local/bin/pqkey attach --foreground",
        )));
        assert!(!managed_unit(&old.replace(
            "ExecStart=/home/a/.cargo/bin/pqkey run",
            "ExecStart=/home/a/.cargo/bin/pqkey start",
        )));
        // As setup wrote a program with a single quote in its path before
        // it refused one, which systemd cannot read: setup's, so replaced.
        let state = crate::state::default_state_dir()
            .to_str()
            .unwrap()
            .replace('%', "%%");
        for exec in [
            "/home/o'brien/pqkey run".to_owned(),
            format!("/home/o'brien/pqkey --state-dir \"{state}\" run"),
        ] {
            assert_eq!(exec_words(&exec), None, "{exec}");
            let unit = old.replace("/home/a/.cargo/bin/pqkey run", &exec);
            assert!(managed_unit(&unit), "{exec}");
            assert!(!managed_unit(
                &unit.replace(" run\n", " run --presence unanswered\n")
            ));
        }
        for exec in [
            "/home/o'brien/pqkey --state-dir \"/retained\" run",
            "/home/o'brien/my pqkey run",
        ] {
            assert!(
                !managed_unit(&old.replace("/home/a/.cargo/bin/pqkey run", exec)),
                "{exec}"
            );
        }
    }

    /// Command lines as systemd 249, 252 and 255 split them into the words
    /// they run (`systemctl --user show -p ExecStart` and the program's own
    /// arguments): at ASCII white space only, with quotes anywhere in a
    /// word, removed; a quote left open, or a backslash, is no word setup
    /// writes.
    #[test]
    fn exec_words_split_command_lines_as_systemd_does() {
        for (line, words) in [
            (
                "/usr/local/bin/pqkey run",
                &["/usr/local/bin/pqkey", "run"][..],
            ),
            ("  a\tb\nc\rd  e ", &["a", "b", "c", "d", "e"]),
            ("/opt/a\u{a0}b/pqkey run", &["/opt/a\u{a0}b/pqkey", "run"]),
            (
                "/home/x\u{3000}y/pqkey run",
                &["/home/x\u{3000}y/pqkey", "run"],
            ),
            ("\"/opt/a b/pqkey\" run", &["/opt/a b/pqkey", "run"]),
            ("'/opt/a b/pqkey' run", &["/opt/a b/pqkey", "run"]),
            ("a'b c'd e", &["ab cd", "e"]),
            ("\"it's\" 'a\"b'", &["it's", "a\"b"]),
            ("", &[]),
        ] {
            let words = words.iter().map(|word| (*word).to_owned()).collect();
            assert_eq!(exec_words(line), Some(words), "{line:?}");
        }
        for line in ["a 'b", "a \"b c", "a\\ b", "'a\\'"] {
            assert_eq!(exec_words(line), None, "{line:?}");
        }
    }

    /// Setup reads its own unit back as written, whatever white space the
    /// program's path holds, which systemd splits at or not, so it never
    /// keeps or names its own unit as the user's. A quote there it refuses,
    /// as systemd does in an executable's name.
    #[test]
    fn setup_reads_its_own_unit_back_as_written() {
        let state = crate::state::default_state_dir()
            .to_str()
            .unwrap()
            .replace('%', "%%");
        for (program, exec) in [
            ("/usr/local/bin/pqkey", "/usr/local/bin/pqkey"),
            ("/opt/a b/pqkey", "\"/opt/a b/pqkey\""),
            ("/opt/a\u{a0}b/pqkey", "/opt/a\u{a0}b/pqkey"),
            ("/home/x\u{3000}y/pqkey", "/home/x\u{3000}y/pqkey"),
            (
                "/opt/x --state-dir y/pqkey",
                "\"/opt/x --state-dir y/pqkey\"",
            ),
            ("/opt/x run/pqkey", "\"/opt/x run/pqkey\""),
            ("/opt/50%/pqkey", "/opt/50%%/pqkey"),
            ("/opt/a;b/pqkey", "/opt/a;b/pqkey"),
            ("/opt/a\u{2028}b/pqkey", "/opt/a\u{2028}b/pqkey"),
        ] {
            let unit = unit_file(Path::new(program)).unwrap();
            let line = unit
                .lines()
                .find_map(|line| line.strip_prefix("ExecStart="))
                .unwrap();
            assert_eq!(line, format!("{exec} --state-dir \"{state}\" run"));
            let escaped = program.replace('%', "%%");
            assert_eq!(
                exec_words(line).unwrap(),
                [escaped.as_str(), "--state-dir", state.as_str(), "run"],
                "{program:?}"
            );
            assert!(managed_unit(&unit), "{program:?}");
        }
        let refused = unit_file(Path::new("/home/o'brien/pqkey")).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            refused.to_string(),
            "the unit cannot run \"/home/o'brien/pqkey\"; install pqkey somewhere else"
        );
    }

    /// Values as `systemctl --user show-environment` printed them on systemd
    /// 249, 252 and 255, after `set-environment` set them, read back as set.
    #[test]
    fn environment_values_systemctl_quotes_are_read_back_as_set() {
        for (shown, value) in [
            (
                "unix:path=/run/user/1000/bus",
                "unix:path=/run/user/1000/bus",
            ),
            ("a,b=c:d/e-f_g.h%20#~{}", "a,b=c:d/e-f_g.h%20#~{}"),
            ("é", "é"),
            (
                "$'unix:path=/tmp/a;unix:path=/tmp/b'",
                "unix:path=/tmp/a;unix:path=/tmp/b",
            ),
            ("$'unix:path=/tmp/q x/bus'", "unix:path=/tmp/q x/bus"),
            ("$'*?[!()$\"'", "*?[!()$\""),
            (r"$'a\'b\\c'", r"a'b\c"),
            (r"$'\a\b\t\n\v\f\r'", "\x07\x08\t\n\x0b\x0c\r"),
            (r"$'a\001b\033c\177'", "a\x01b\x1bc\x7f"),
        ] {
            assert_eq!(shown_value(shown), value, "{shown}");
        }
    }

    /// Setup replaces an installed unit only if, apart from `ExecStart=`, it
    /// matches the template or an entry of `EARLIER_UNITS` line for line,
    /// comments included; any other it keeps as the user's own. A template
    /// change that does not add the unit it replaces to `EARLIER_UNITS` would
    /// leave every existing installation on that unit without a word, so the
    /// template's bytes are pinned here.
    #[test]
    fn template_changes_add_the_replaced_unit_to_earlier_units() {
        use sha2::{Digest, Sha256};
        let digest: String = Sha256::digest(UNIT_TEMPLATE.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest, "257e51e450c816f5cf72e141987808aa9293ccaf2d6d61727b12ae4b73794bb7",
            "contrib/systemd/user/pqkey.service changed, and setup upgrades only installed units \
             that match it or an entry of EARLIER_UNITS. Copy its previous version to \
             crates/pqkey/src/platform/linux/earlier-units/<date it first shipped>.service, like \
             2026-10-05.service, or to <date>-<commit>.service where that date has more than \
             one, like 2026-10-01-c591936.service; add that file to EARLIER_UNITS, then replace \
             the SHA-256 in this test with the new one (left)"
        );
    }

    /// The child of the tests of [`UserService::problems`], through the fake
    /// systemctl of [`problems_of`]: it prints what it finds, with the key
    /// running or not as `PQKEY_PROBLEMS_CHILD` says.
    #[test]
    fn service_problems_child() {
        let Some(running) = env::var_os("PQKEY_PROBLEMS_CHILD") else {
            return;
        };
        for problem in UserService::problems(running == "running").unwrap() {
            println!("\nPROBLEM\t{}\t{}", problem.what, problem.fix);
        }
    }

    /// What [`UserService::problems`] finds, with the key `running` or not,
    /// for a unit that `systemctl --user show` reports as `shown`, or with a
    /// query that fails for `None`, and for a user whose `Linger` property
    /// `loginctl show-user` reports as `linger`, or cannot for `None`; with
    /// the calls it made. No unit file is where setup installs it.
    fn problems_with(
        shown: Option<&str>,
        linger: Option<&str>,
        running: bool,
    ) -> (Vec<Problem>, Vec<String>) {
        use crate::test_support::TempDir;
        let dir = TempDir::new("service-problems");
        problems_in(dir.path(), shown, linger, running)
    }

    /// [`problems_with`] in `dir`, where the user's configuration directory
    /// (XDG_CONFIG_HOME) is `dir/config`.
    fn problems_in(
        dir: &Path,
        shown: Option<&str>,
        linger: Option<&str>,
        running: bool,
    ) -> (Vec<Problem>, Vec<String>) {
        use std::os::unix::fs::PermissionsExt;
        for (name, script) in [
            (
                "systemctl",
                r#"#!/bin/sh
printf 'systemctl %s\n' "$*" >> "$COMMAND_TRACE"
[ -n "${UNIT_SHOWN+set}" ] || { echo "Failed to connect to bus: No medium found" >&2; exit 1; }
printf '%s\n' "$UNIT_SHOWN"
"#,
            ),
            (
                "loginctl",
                r#"#!/bin/sh
printf 'loginctl %s\n' "$*" >> "$COMMAND_TRACE"
[ -n "${LINGER+set}" ] || { echo "Failed to get user: User ID $2 is not logged in or lingering" >&2; exit 1; }
printf '%s\n' "$LINGER"
"#,
            ),
        ] {
            let path = dir.join(name);
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let trace = dir.join("trace");
        let _ = fs::remove_file(&trace);
        let mut child = ProcessCommand::new(env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "platform::linux::daemon::setup_tests::service_problems_child",
                "--nocapture",
            ])
            .env(
                "PQKEY_PROBLEMS_CHILD",
                if running { "running" } else { "stopped" },
            )
            .env("PATH", dir)
            .env("XDG_CONFIG_HOME", dir.join("config"))
            .env("COMMAND_TRACE", &trace)
            .env_remove("UNIT_SHOWN")
            .env_remove("LINGER");
        if let Some(shown) = shown {
            child.env("UNIT_SHOWN", shown);
        }
        if let Some(linger) = linger {
            child.env("LINGER", linger);
        }
        let output = child.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let problems = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix("PROBLEM\t")?.split_once('\t'))
            .map(|(what, fix)| Problem::new(what, fix))
            .collect();
        let calls = fs::read_to_string(&trace)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        (problems, calls)
    }

    /// The query of the unit with which [`UserService::problems`] starts.
    fn show_call() -> String {
        format!("systemctl --user show --property {UNIT_STATE} pqkey.service")
    }

    /// [`problems_with`] for a unit that is enabled, or neither loaded nor
    /// masked, for which only systemctl is asked, once.
    fn problems_of(shown: Option<&str>, running: bool) -> Vec<Problem> {
        let (problems, calls) = problems_with(shown, None, running);
        assert_eq!(calls, [show_call()]);
        problems
    }

    /// [`problems_with`] for a unit that is masked or not enabled, for which
    /// loginctl is asked next whether this user lingers.
    fn problems_lingering(shown: &str, linger: Option<&str>, running: bool) -> Vec<Problem> {
        let (problems, calls) = problems_with(Some(shown), linger, running);
        assert_eq!(
            calls,
            [
                show_call(),
                format!(
                    "loginctl show-user {} --property=Linger --value",
                    unistd::getuid()
                )
            ]
        );
        problems
    }

    /// What `systemctl --user show --property UNIT_STATE pqkey.service`
    /// prints for a unit in this state: systemd 249, 252 and 255 list the
    /// properties in this order.
    fn shown(
        load: &str,
        file: &str,
        active: &str,
        sub: &str,
        result: &str,
        status: &str,
    ) -> String {
        format!(
            "Result={result}\nExecMainStatus={status}\nLoadState={load}\nActiveState={active}\n\
             SubState={sub}\nUnitFileState={file}"
        )
    }

    /// A unit that failed is named with how, where the cause is logged and
    /// `pqkey start`, which resets the failed state, for every result: a key
    /// that exited, as when systemd gave up restarting it after five starts
    /// within a minute (`Result=exit-code`, not `start-limit-hit`, as systemd
    /// 249 to 255 report it) or after status 3, on which it does not restart
    /// it; a key that was killed; a start that systemd refused
    /// (`start-limit-hit`); and any other. While a key runs, which here can
    /// only be one started by hand, its own problem says what to do instead.
    #[test]
    fn status_names_a_failed_service_with_its_log_and_pqkey_start() {
        for (result, status, failed) in [
            ("exit-code", "1", "failed: the key exited with status 1"),
            ("exit-code", "3", "failed: the key exited with status 3"),
            ("signal", "9", "failed: the key was killed by signal 9"),
            ("core-dump", "11", "failed: the key was killed by signal 11"),
            (
                "start-limit-hit",
                "15",
                "failed with result 'start-limit-hit'",
            ),
            ("timeout", "0", "failed with result 'timeout'"),
        ] {
            let unit = shown("loaded", "enabled", "failed", "failed", result, status);
            assert_eq!(
                problems_of(Some(&unit), false),
                [Problem::new(
                    format!("the systemd user service pqkey.service {failed}"),
                    "see why in `journalctl --user -u pqkey`, fix that, then run `pqkey start`",
                )],
                "{result}"
            );
            let running = problems_of(Some(&unit), true);
            assert!(running.is_empty(), "{result}: {running:?}");
        }
    }

    /// A unit that failed and that systemd is about to restart, waiting out
    /// `RestartSec=` (`auto-restart`) or with the restart queued
    /// (`auto-restart-queued`, systemd 254 and later), is named with how it
    /// failed, its log and `pqkey start`. One that is starting is not.
    #[test]
    fn status_names_a_service_that_systemd_restarts_after_a_failure() {
        for (sub, result, status, failed) in [
            (
                "auto-restart",
                "exit-code",
                "1",
                "failed: the key exited with status 1",
            ),
            (
                "auto-restart-queued",
                "signal",
                "9",
                "failed: the key was killed by signal 9",
            ),
        ] {
            let unit = shown("loaded", "enabled", "activating", sub, result, status);
            assert_eq!(
                problems_of(Some(&unit), false),
                [Problem::new(
                    format!(
                        "the systemd user service pqkey.service {failed}; systemd is restarting it"
                    ),
                    FAILED_FIX,
                )],
                "{sub}"
            );
            let running = problems_of(Some(&unit), true);
            assert!(running.is_empty(), "{sub}: {running:?}");
        }
        let starting = shown("loaded", "enabled", "activating", "start", "success", "0");
        let found = problems_of(Some(&starting), false);
        assert!(found.is_empty(), "{found:?}");
    }

    /// A unit that is not enabled, after `systemctl --user disable pqkey`, or
    /// linked from outside systemd's directories but not enabled, does not
    /// start with the session. Where the user's service manager lingers,
    /// SECURITY.md advises exactly that, so it is not named. Otherwise it is,
    /// whether the key runs or not, and beside a failure: with `pqkey setup`,
    /// which enables it, where the user does not linger, and with that
    /// advice as the exception where loginctl cannot tell, as for a user
    /// without a session. An enabled unit is not named, and loginctl is not
    /// asked.
    #[test]
    fn status_names_a_service_that_is_not_enabled_unless_the_user_lingers() {
        let what = "the systemd user service pqkey.service is not enabled, so the key does not \
                    start with your session";
        let not_lingering = Problem::new(what, "run `pqkey setup`");
        let unknown = Problem::new(
            what,
            "run `pqkey setup`; but if lingering is on (`loginctl enable-linger`) and you \
             disabled it as SECURITY.md advises, leave it and use `pqkey start`",
        );
        for file in ["disabled", "linked", "linked-runtime"] {
            let unit = shown("loaded", file, "inactive", "dead", "success", "0");
            for running in [false, true] {
                assert_eq!(
                    problems_lingering(&unit, Some("no"), running),
                    std::slice::from_ref(&not_lingering),
                    "{file}"
                );
                let lingers = problems_lingering(&unit, Some("yes"), running);
                assert!(lingers.is_empty(), "{file}: {lingers:?}");
                // loginctl fails, or answers something else.
                for linger in [None, Some("")] {
                    assert_eq!(
                        problems_lingering(&unit, linger, running),
                        std::slice::from_ref(&unknown),
                        "{file} {linger:?}"
                    );
                }
            }
        }
        let failed = shown("loaded", "disabled", "failed", "failed", "exit-code", "1");
        let failure = Problem::new(
            "the systemd user service pqkey.service failed: the key exited with status 1",
            FAILED_FIX,
        );
        assert_eq!(
            problems_lingering(&failed, Some("no"), false),
            [not_lingering, failure.clone()]
        );
        assert_eq!(problems_lingering(&failed, Some("yes"), false), [failure]);
        for (running, active, sub) in [(false, "inactive", "dead"), (true, "active", "running")] {
            let enabled = shown("loaded", "enabled", active, sub, "success", "0");
            let found = problems_of(Some(&enabled), running);
            assert!(found.is_empty(), "{found:?}");
        }
    }

    /// A masked unit, an empty unit file or a link to /dev/null, whether in
    /// the user's configuration or in /run (`masked-runtime`), is named
    /// whether the key runs, as a key started by hand can, or not, with
    /// `systemctl --user unmask pqkey`, then `pqkey setup`, which installs
    /// the unit again and enables it. Where the user's service manager
    /// lingers, the fix goes on to disable it, as SECURITY.md advises; where
    /// loginctl cannot tell, it names that as the exception.
    #[test]
    fn status_names_a_masked_service_with_unmask_and_setup() {
        let unmask_and_setup = "run `systemctl --user unmask pqkey`, then `pqkey setup`";
        for (linger, fix) in [
            (Some("no"), unmask_and_setup.to_owned()),
            (
                Some("yes"),
                format!(
                    "{unmask_and_setup}, then `systemctl --user disable pqkey`, as SECURITY.md \
                     advises with lingering"
                ),
            ),
            (
                None,
                format!(
                    "{unmask_and_setup}; but if lingering is on (`loginctl enable-linger`), then \
                     also `systemctl --user disable pqkey`, as SECURITY.md advises"
                ),
            ),
        ] {
            for file in ["masked", "masked-runtime"] {
                let unit = shown("masked", file, "inactive", "dead", "success", "0");
                for running in [false, true] {
                    assert_eq!(
                        problems_lingering(&unit, linger, running),
                        [Problem::new(
                            "the systemd user service pqkey.service is masked, so the key does \
                             not start with your session",
                            fix.as_str(),
                        )],
                        "{file} {linger:?}"
                    );
                }
            }
        }
    }

    /// A unit that is not installed, or that systemd cannot load, and a
    /// user manager that cannot be asked, leave the key without its service,
    /// which `pqkey setup` installs.
    #[test]
    fn status_names_a_missing_service_with_setup() {
        let missing = [Problem::new(
            "the key does not start with your session",
            "run `pqkey setup`",
        )];
        for load in ["not-found", "bad-setting"] {
            let unit = shown(load, "", "inactive", "dead", "success", "0");
            assert_eq!(problems_of(Some(&unit), false), missing, "{load}");
        }
        for running in [false, true] {
            assert_eq!(problems_of(None, running), missing);
        }
    }

    /// A unit file where setup installs the unit that systemd does not find
    /// has lost the link setup made to it, as `systemctl --user disable
    /// pqkey`, SECURITY.md's advice where the user lingers, removes it for a
    /// unit outside systemd's own directory. `pqkey start` then starts the
    /// key by hand. Where the user lingers, the fix links it again, which
    /// does not enable it; where that is not known, the fix says so; and
    /// otherwise it is `pqkey setup`, as for a unit that is not installed.
    /// Only for a regular file: systemd links no other, and loginctl is not
    /// asked for any other unit that is not loaded.
    #[test]
    fn status_names_a_unit_systemd_does_not_find_with_link_where_the_user_lingers() {
        use crate::test_support::TempDir;
        let dir = TempDir::new("service-unlinked");
        let path = dir.path().join("config/systemd/user/pqkey.service");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, UNIT_TEMPLATE).unwrap();
        let link = format!("`systemctl --user link '{}'`", path.display());
        let what = "the key does not start with your session";
        let not_found = shown("not-found", "", "inactive", "dead", "success", "0");
        let linger_call = format!(
            "loginctl show-user {} --property=Linger --value",
            unistd::getuid()
        );
        for running in [false, true] {
            for (linger, problem) in [
                (Some("no"), Problem::new(what, "run `pqkey setup`")),
                (
                    Some("yes"),
                    Problem::new(
                        "the systemd user service pqkey.service is not found, so `pqkey start` \
                         starts the key by hand instead of through it",
                        format!(
                            "run {link}, which does not enable it, as SECURITY.md advises with \
                             lingering"
                        ),
                    ),
                ),
                (
                    None,
                    Problem::new(
                        what,
                        format!(
                            "run `pqkey setup`; but if lingering is on (`loginctl \
                             enable-linger`) and you disabled it as SECURITY.md advises, run \
                             {link} instead"
                        ),
                    ),
                ),
                (
                    Some(""),
                    Problem::new(
                        what,
                        format!(
                            "run `pqkey setup`; but if lingering is on (`loginctl \
                             enable-linger`) and you disabled it as SECURITY.md advises, run \
                             {link} instead"
                        ),
                    ),
                ),
            ] {
                let (problems, calls) = problems_in(dir.path(), Some(&not_found), linger, running);
                assert_eq!(problems, [problem], "{linger:?} {running}");
                assert_eq!(calls, [show_call(), linger_call.clone()], "{linger:?}");
            }
        }
        // A unit systemd cannot load, a failed query, or a link where setup
        // installs the unit: `pqkey setup`, without asking loginctl.
        let bad = shown("bad-setting", "", "inactive", "dead", "success", "0");
        for query in [Some(bad.as_str()), None] {
            let (problems, calls) = problems_in(dir.path(), query, Some("yes"), false);
            assert_eq!(problems, [Problem::new(what, "run `pqkey setup`")]);
            assert_eq!(calls, [show_call()]);
        }
        fs::rename(&path, dir.path().join("elsewhere.service")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere.service"), &path).unwrap();
        let (problems, calls) = problems_in(dir.path(), Some(&not_found), Some("yes"), false);
        assert_eq!(problems, [Problem::new(what, "run `pqkey setup`")]);
        assert_eq!(calls, [show_call()]);
    }
}
