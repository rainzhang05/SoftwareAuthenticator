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
    let exec = if escaped.contains(' ') {
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
/// installed as it is. Returns whether it changed.
fn install_unit(binary: &Path) -> io::Result<bool> {
    let unit = unit_file(binary)?;
    let dir = unit_dir();
    let path = dir.join(UNIT);
    let installed = match fs::read_to_string(&path) {
        Ok(installed) => Some(installed),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };
    if let Some(installed) = installed {
        if installed == unit {
            // A prior write may have succeeded while daemon-reload failed.
            systemctl(&[
                "link",
                path.to_str()
                    .ok_or_else(|| io::Error::other("unit path is not UTF-8"))?,
            ])?;
            systemctl(&["daemon-reload"])?;
            return Ok(false);
        }
        if !managed_unit(&installed) {
            // Keep custom arguments and policy. Setup verifies the resulting
            // daemon's identity and readiness rather than replacing them.
            systemctl(&[
                "link",
                path.to_str()
                    .ok_or_else(|| io::Error::other("unit path is not UTF-8"))?,
            ])?;
            systemctl(&["daemon-reload"])?;
            return Ok(false);
        }
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
    systemctl(&[
        "link",
        path.to_str()
            .ok_or_else(|| io::Error::other("unit path is not UTF-8"))?,
    ])?;
    drop(systemctl(&["daemon-reload"])?);
    Ok(true)
}

/// Only units matching the shipped template (apart from ExecStart) are
/// rewritten. User drop-ins remain under systemd's control.
fn managed_unit(unit: &str) -> bool {
    let without_exec = |text: &str| {
        text.lines()
            .filter(|line| !line.starts_with("ExecStart="))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let one_word = |word: &str| {
        if let Some(inner) = word
            .strip_prefix('"')
            .and_then(|word| word.strip_suffix('"'))
        {
            !inner.contains('"')
        } else {
            !word.is_empty() && !word.chars().any(char::is_whitespace)
        }
    };
    let exec = unit
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart="))
        .and_then(|line| line.strip_suffix(" run"));
    let ordinary_exec = exec.is_some_and(|exec| match exec.split_once(" --state-dir ") {
        Some((binary, state)) => one_word(binary) && one_word(state),
        None => one_word(exec),
    });
    ordinary_exec && without_exec(unit) == without_exec(UNIT_TEMPLATE)
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
    /// Ensure the daemon uses the desktop bus setup checked in this shell.
    pub fn prepare_session() -> io::Result<bool> {
        if let Some(address) = env::var_os("DBUS_SESSION_BUS_ADDRESS") {
            let address = address
                .to_str()
                .ok_or_else(|| io::Error::other("session bus address is not UTF-8"))?;
            let wanted = format!("DBUS_SESSION_BUS_ADDRESS={address}");
            let current = systemctl(&["show-environment"])?;
            if !current.lines().any(|line| line == wanted) {
                systemctl(&["set-environment", &wanted])?;
                return Ok(true);
            }
        }
        Ok(false)
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
            let changed = UserService::install(Path::new("/usr/local/bin/pqkey"))?;
            println!("CHANGED:{changed}");
            UserService::prepare_session()?;
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
        let commands = fs::read_to_string(&trace).unwrap();
        assert!(commands.contains("--user link"));
        assert!(commands.contains(
            "--user set-environment DBUS_SESSION_BUS_ADDRESS=unix:path=/fixture/bus:unset"
        ));
        assert!(commands.contains("--user enable pqkey.service:unset"));
        let custom = fs::read_to_string(&unit)
            .unwrap()
            .replace(" run\n", " run --presence unanswered\n");
        fs::write(&unit, &custom).unwrap();
        assert!(child("").status.success());
        assert_eq!(fs::read_to_string(&unit).unwrap(), custom);
        for action in ["link", "enable", "set-environment"] {
            assert_eq!(child(action).status.code(), Some(1), "{action}");
            assert_eq!(fs::read_to_string(&unit).unwrap(), custom);
        }
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
    }
}
