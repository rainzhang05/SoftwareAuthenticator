//! The systemd user service and Linux startup access warnings.
use super::permissions;
use crate::{
    cli::{checks::Problem, output::errln},
    platform::ServiceAction,
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

/// Where the user's systemd units live.
fn unit_dir() -> PathBuf {
    match env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".config"),
    }
    .join("systemd/user")
}

/// The unit, running `binary`.
pub(crate) fn unit_file(binary: &Path) -> io::Result<String> {
    let path = binary.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not valid UTF-8", binary.display()),
        )
    })?;
    if path
        .chars()
        .any(|c| c.is_control() || c == '"' || c == '\\')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the unit cannot run {path:?}; install pqkey somewhere else"),
        ));
    }
    // systemd expands % specifiers in ExecStart, and splits it at spaces
    // outside quotes.
    let escaped = path.replace('%', "%%");
    let exec = if escaped.contains(' ') {
        format!("ExecStart=\"{escaped}\" run")
    } else {
        format!("ExecStart={escaped} run")
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
/// installed as it is. Returns whether it changed.
fn install_unit(binary: &Path) -> io::Result<bool> {
    let unit = unit_file(binary)?;
    let dir = unit_dir();
    let path = dir.join(UNIT);
    if fs::read_to_string(&path).is_ok_and(|installed| installed == unit) {
        return Ok(false);
    }
    fs::create_dir_all(&dir)?;
    let temporary = dir.join(format!(".{UNIT}.{}", std::process::id()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temporary)?
        .write_all(unit.as_bytes())?;
    fs::rename(&temporary, &path)?;
    drop(systemctl(&["daemon-reload"])?);
    Ok(true)
}

/// Run `systemctl --user` with `args`, failing with its message.
pub fn systemctl(args: &[&str]) -> io::Result<String> {
    let output = ProcessCommand::new("systemctl")
        .arg("--user")
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    } else {
        Err(io::Error::other(format!(
            "systemctl --user {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// A property of the user unit, if systemd answers.
fn unit_property(property: &str) -> Option<String> {
    systemctl(&["show", "--property", property, "--value", UNIT]).ok()
}

/// The pid of the user service's daemon, if it runs.
fn unit_main_pid() -> Option<Pid> {
    unit_property("MainPID")
        .and_then(|pid| pid.parse::<i32>().ok())
        .filter(|pid| *pid > 0)
        .map(Pid::from_raw)
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
    pub fn installed() -> io::Result<bool> {
        Ok(unit_property("LoadState").as_deref() == Some("loaded"))
    }
    pub fn main_pid() -> io::Result<Option<Pid>> {
        Ok(unit_main_pid())
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
    pub(crate) fn manual_start_problem(pid: Pid) -> io::Result<Problem> {
        Ok(Problem {
            what: format!(
                "the key (pid {pid}) was started by hand, so the systemd user service cannot run it"
            ),
            fix: "run `pqkey stop && pqkey start`".into(),
        })
    }
}

pub(crate) const START_HELP: &str =
    "Plug the key in: start it, through its systemd user service when that is installed";
pub(crate) const RUN_HELP: &str =
    "Run the key in the foreground until it is stopped (for the systemd unit and test rigs)";
pub(crate) const PRESENCE_NOTIFY_HELP: &str = "Ask with a desktop notification that has Approve \
    and Deny buttons. Without a session bus and a notification server that can show buttons, \
    every request is denied";
